#include "zip_analyzer.h"

#include <ctype.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>

#define AF_ZIP_EOCD_SIGNATURE       0x06054b50u
#define AF_ZIP64_EOCD_SIGNATURE     0x06064b50u
#define AF_ZIP64_LOC_SIGNATURE      0x07064b50u
#define AF_ZIP_CDIR_SIGNATURE       0x02014b50u
#define AF_ZIP_LOCAL_SIGNATURE      0x04034b50u
#define AF_ZIP_EOCD_MIN_SIZE        22u
#define AF_ZIP64_LOC_SIZE           20u
#define AF_ZIP_MAX_COMMENT          65535u
#define AF_ZIP_CDIR_FIXED_SIZE      46u
#define AF_ZIP_LOCAL_FIXED_SIZE     30u
#define AF_ZIP64_EXTRA_ID           0x0001u
#define AF_NESTED_BUFFER_LIMIT      (8u * 1024u * 1024u)

static uint16_t read_u16_le(const unsigned char *p)
{
    return (uint16_t)((uint16_t)p[0] | ((uint16_t)p[1] << 8));
}

static uint32_t read_u32_le(const unsigned char *p)
{
    return (uint32_t)p[0]
        | ((uint32_t)p[1] << 8)
        | ((uint32_t)p[2] << 16)
        | ((uint32_t)p[3] << 24);
}

static uint64_t read_u64_le(const unsigned char *p)
{
    return (uint64_t)read_u32_le(p) | ((uint64_t)read_u32_le(p + 4) << 32);
}

static int add_u64(uint64_t *target, uint64_t value)
{
    if (UINT64_MAX - *target < value)
    {
        *target = UINT64_MAX;
        return -1;
    }
    *target += value;
    return 0;
}

static void append_note(char *notes, size_t notes_size, const char *text)
{
    size_t used;
    if (notes == NULL || notes_size == 0 || text == NULL)
    {
        return;
    }
    used = strlen(notes);
    if (used < notes_size - 1)
    {
        strncat(notes, text, notes_size - used - 1);
    }
}

static int read_exact(FILE *fp, uint64_t offset, unsigned char *buffer, size_t size)
{
    if (offset > (uint64_t)LONG_MAX)
    {
        return -1;
    }
    if (fseek(fp, (long)offset, SEEK_SET) != 0)
    {
        return -1;
    }
    return fread(buffer, 1, size, fp) == size ? 0 : -1;
}

static int find_eocd(FILE *fp, uint64_t file_size, uint64_t *eocd_offset, unsigned char eocd[AF_ZIP_EOCD_MIN_SIZE])
{
    uint64_t search_size_u64;
    uint64_t search_start;
    size_t search_size;
    unsigned char *buffer;
    size_t i;
    int retVal = -1;

    if (file_size < AF_ZIP_EOCD_MIN_SIZE)
    {
        return -1;
    }
    search_size_u64 = file_size;
    if (search_size_u64 > (uint64_t)AF_ZIP_MAX_COMMENT + AF_ZIP_EOCD_MIN_SIZE)
    {
        search_size_u64 = (uint64_t)AF_ZIP_MAX_COMMENT + AF_ZIP_EOCD_MIN_SIZE;
    }
    search_size = (size_t)search_size_u64;
    search_start = file_size - search_size_u64;
    buffer = (unsigned char *)malloc(search_size);
    if (buffer == NULL)
    {
        return -2;
    }
    if (read_exact(fp, search_start, buffer, search_size) != 0)
    {
        free(buffer);
        return -1;
    }

    i = search_size - AF_ZIP_EOCD_MIN_SIZE;
    for (;;)
    {
        if (read_u32_le(buffer + i) == AF_ZIP_EOCD_SIGNATURE)
        {
            uint16_t comment_len = read_u16_le(buffer + i + 20);
            if (i + AF_ZIP_EOCD_MIN_SIZE + comment_len == search_size)
            {
                memcpy(eocd, buffer + i, AF_ZIP_EOCD_MIN_SIZE);
                *eocd_offset = search_start + i;
                retVal = 0;
                break;
            }
        }
        if (i == 0)
        {
            break;
        }
        i--;
    }
    free(buffer);
    return retVal;
}

static int parse_zip64_root(FILE *fp, uint64_t eocd_offset, uint64_t file_size,
                            uint64_t *entries_total, uint64_t *cdir_size, uint64_t *cdir_offset)
{
    unsigned char locator[AF_ZIP64_LOC_SIZE];
    unsigned char record[56];
    uint64_t record_offset;

    if (eocd_offset < AF_ZIP64_LOC_SIZE)
    {
        return -1;
    }
    if (read_exact(fp, eocd_offset - AF_ZIP64_LOC_SIZE, locator, sizeof(locator)) != 0 ||
        read_u32_le(locator) != AF_ZIP64_LOC_SIGNATURE)
    {
        return -1;
    }
    if (read_u32_le(locator + 4) != 0 || read_u32_le(locator + 16) != 1)
    {
        return -2;
    }
    record_offset = read_u64_le(locator + 8);
    if (record_offset > file_size || file_size - record_offset < sizeof(record))
    {
        return -1;
    }
    if (read_exact(fp, record_offset, record, sizeof(record)) != 0 ||
        read_u32_le(record) != AF_ZIP64_EOCD_SIGNATURE)
    {
        return -1;
    }
    if (read_u32_le(record + 16) != 0 || read_u32_le(record + 20) != 0)
    {
        return -2;
    }
    if (read_u64_le(record + 24) != read_u64_le(record + 32))
    {
        return -2;
    }
    *entries_total = read_u64_le(record + 32);
    *cdir_size = read_u64_le(record + 40);
    *cdir_offset = read_u64_le(record + 48);
    return 0;
}

static int has_zip_extension(const unsigned char *name, size_t len)
{
    const char suffix[] = ".zip";
    size_t i;
    if (len < 4)
    {
        return 0;
    }
    for (i = 0; i < 4; i++)
    {
        if ((unsigned char)tolower(name[len - 4 + i]) != (unsigned char)suffix[i])
        {
            return 0;
        }
    }
    return 1;
}

static int is_absolute_path(const unsigned char *name, size_t len)
{
    if (len == 0)
    {
        return 0;
    }
    if (name[0] == '/' || name[0] == '\\')
    {
        return 1;
    }
    return len >= 3 && isalpha(name[0]) && name[1] == ':' && (name[2] == '/' || name[2] == '\\');
}

static int has_parent_traversal(const unsigned char *name, size_t len)
{
    size_t start = 0;
    size_t i;
    for (i = 0; i <= len; i++)
    {
        if (i == len || name[i] == '/' || name[i] == '\\')
        {
            size_t part_len = i - start;
            if (part_len == 2 && name[start] == '.' && name[start + 1] == '.')
            {
                return 1;
            }
            start = i + 1;
        }
    }
    return 0;
}

static int parse_zip64_extra(const unsigned char *extra, size_t extra_len,
                             uint32_t raw_uncompressed, uint32_t raw_compressed, uint32_t raw_offset,
                             uint64_t *uncompressed, uint64_t *compressed, uint64_t *local_offset)
{
    size_t cursor = 0;
    while (cursor + 4 <= extra_len)
    {
        uint16_t id = read_u16_le(extra + cursor);
        uint16_t size = read_u16_le(extra + cursor + 2);
        size_t pos = cursor + 4;
        size_t end = pos + size;
        if (end > extra_len)
        {
            return -1;
        }
        if (id == AF_ZIP64_EXTRA_ID)
        {
            if (raw_uncompressed == 0xffffffffu)
            {
                if (pos + 8 > end) return -1;
                *uncompressed = read_u64_le(extra + pos);
                pos += 8;
            }
            if (raw_compressed == 0xffffffffu)
            {
                if (pos + 8 > end) return -1;
                *compressed = read_u64_le(extra + pos);
                pos += 8;
            }
            if (raw_offset == 0xffffffffu)
            {
                if (pos + 8 > end) return -1;
                *local_offset = read_u64_le(extra + pos);
            }
            return 0;
        }
        cursor = end;
    }
    return (raw_uncompressed == 0xffffffffu || raw_compressed == 0xffffffffu || raw_offset == 0xffffffffu) ? -1 : 0;
}

static int inspect_stored_nested_zip(FILE *fp, uint64_t local_offset, uint64_t compressed_size,
                                     unsigned int depth, AfZipMetrics *metrics)
{
    unsigned char local[AF_ZIP_LOCAL_FIXED_SIZE];
    uint16_t name_len;
    uint16_t extra_len;
    uint64_t data_offset;
    unsigned char signature[4];

    if (depth > AF_MAX_NESTED_DEPTH || metrics->nested_archives_inspected >= AF_MAX_NESTED_ARCHIVES)
    {
        metrics->recursion_limit_hit = 1;
        return 0;
    }
    if (compressed_size < 4 || compressed_size > AF_NESTED_BUFFER_LIMIT)
    {
        return 0;
    }
    if (read_exact(fp, local_offset, local, sizeof(local)) != 0 || read_u32_le(local) != AF_ZIP_LOCAL_SIGNATURE)
    {
        return 0;
    }
    name_len = read_u16_le(local + 26);
    extra_len = read_u16_le(local + 28);
    data_offset = local_offset + AF_ZIP_LOCAL_FIXED_SIZE + name_len + extra_len;
    if (read_exact(fp, data_offset, signature, sizeof(signature)) != 0 || read_u32_le(signature) != AF_ZIP_LOCAL_SIGNATURE)
    {
        return 0;
    }

    /* v0.3 stays metadata-only: count confirmed nested ZIP signatures without decoding them. */
    metrics->nested_archives_inspected++;
    metrics->nested_entries_total++;
    if (depth > metrics->maximum_nested_depth)
    {
        metrics->maximum_nested_depth = depth;
    }
    return 1;
}

int af_analyze_zip(FILE *fp, uint64_t file_size, AfZipMetrics *metrics, char *notes, size_t notes_size)
{
    unsigned char eocd[AF_ZIP_EOCD_MIN_SIZE];
    uint64_t eocd_offset = 0;
    uint16_t disk_no;
    uint16_t cdir_disk_no;
    uint16_t entries_disk16;
    uint16_t entries_total16;
    uint32_t cdir_size32;
    uint32_t cdir_offset32;
    uint64_t entries_total;
    uint64_t cdir_size;
    uint64_t cdir_offset;
    uint64_t cursor;
    uint64_t cdir_end;
    uint64_t i;

    if (fp == NULL || metrics == NULL)
    {
        return -1;
    }
    memset(metrics, 0, sizeof(*metrics));

    if (find_eocd(fp, file_size, &eocd_offset, eocd) != 0)
    {
        append_note(notes, notes_size, "ZIP end-of-central-directory record not found. ");
        return -2;
    }
    disk_no = read_u16_le(eocd + 4);
    cdir_disk_no = read_u16_le(eocd + 6);
    entries_disk16 = read_u16_le(eocd + 8);
    entries_total16 = read_u16_le(eocd + 10);
    cdir_size32 = read_u32_le(eocd + 12);
    cdir_offset32 = read_u32_le(eocd + 16);

    if (disk_no != 0 || cdir_disk_no != 0 || (entries_disk16 != entries_total16 && entries_total16 != 0xffffu))
    {
        append_note(notes, notes_size, "Multi-disk ZIP archives are not supported. ");
        return -3;
    }

    entries_total = entries_total16;
    cdir_size = cdir_size32;
    cdir_offset = cdir_offset32;
    if (entries_total16 == 0xffffu || cdir_size32 == 0xffffffffu || cdir_offset32 == 0xffffffffu)
    {
        metrics->zip64_detected = 1;
        if (parse_zip64_root(fp, eocd_offset, file_size, &entries_total, &cdir_size, &cdir_offset) != 0)
        {
            append_note(notes, notes_size, "ZIP64 root metadata is incomplete or unsupported. ");
            return -4;
        }
        metrics->zip64_valid = 1;
        append_note(notes, notes_size, "ZIP64 root metadata validated. ");
    }

    if (cdir_offset > file_size || cdir_size > file_size - cdir_offset)
    {
        append_note(notes, notes_size, "Central-directory bounds are inconsistent with file size. ");
        return -5;
    }
    cdir_end = cdir_offset + cdir_size;
    if (cdir_end > eocd_offset && !metrics->zip64_detected)
    {
        append_note(notes, notes_size, "Central directory overlaps the end record. ");
        return -5;
    }

    cursor = cdir_offset;
    for (i = 0; i < entries_total; i++)
    {
        unsigned char fixed[AF_ZIP_CDIR_FIXED_SIZE];
        uint32_t raw_compressed;
        uint32_t raw_uncompressed;
        uint32_t raw_local_offset;
        uint64_t compressed_size;
        uint64_t uncompressed_size;
        uint64_t local_offset;
        uint16_t method;
        uint16_t filename_len;
        uint16_t extra_len;
        uint16_t comment_len;
        uint64_t record_size;
        unsigned char *variable = NULL;
        unsigned char *name;
        unsigned char *extra;
        double ratio;

        if (cursor > cdir_end || cdir_end - cursor < AF_ZIP_CDIR_FIXED_SIZE)
        {
            append_note(notes, notes_size, "Central directory ended before all declared entries were parsed. ");
            return -6;
        }
        if (read_exact(fp, cursor, fixed, sizeof(fixed)) != 0 || read_u32_le(fixed) != AF_ZIP_CDIR_SIGNATURE)
        {
            append_note(notes, notes_size, "Invalid central-directory entry. ");
            return -7;
        }

        method = read_u16_le(fixed + 10);
        raw_compressed = read_u32_le(fixed + 20);
        raw_uncompressed = read_u32_le(fixed + 24);
        filename_len = read_u16_le(fixed + 28);
        extra_len = read_u16_le(fixed + 30);
        comment_len = read_u16_le(fixed + 32);
        raw_local_offset = read_u32_le(fixed + 42);
        compressed_size = raw_compressed;
        uncompressed_size = raw_uncompressed;
        local_offset = raw_local_offset;

        record_size = (uint64_t)AF_ZIP_CDIR_FIXED_SIZE + filename_len + extra_len + comment_len;
        if (record_size > cdir_end - cursor)
        {
            append_note(notes, notes_size, "Central-directory entry extends beyond directory bounds. ");
            return -8;
        }
        if ((uint64_t)filename_len + extra_len > SIZE_MAX)
        {
            return -9;
        }
        variable = (unsigned char *)malloc((size_t)filename_len + extra_len + 1);
        if (variable == NULL)
        {
            return -10;
        }
        if (read_exact(fp, cursor + AF_ZIP_CDIR_FIXED_SIZE, variable, (size_t)filename_len + extra_len) != 0)
        {
            free(variable);
            return -11;
        }
        variable[filename_len + extra_len] = 0;
        name = variable;
        extra = variable + filename_len;

        if (raw_compressed == 0xffffffffu || raw_uncompressed == 0xffffffffu || raw_local_offset == 0xffffffffu)
        {
            metrics->zip64_detected = 1;
            if (parse_zip64_extra(extra, extra_len, raw_uncompressed, raw_compressed, raw_local_offset,
                                  &uncompressed_size, &compressed_size, &local_offset) != 0)
            {
                free(variable);
                append_note(notes, notes_size, "ZIP64 entry metadata is incomplete. ");
                return -12;
            }
            metrics->zip64_valid = 1;
        }

        metrics->entry_count++;
        add_u64(&metrics->total_compressed_size, compressed_size);
        add_u64(&metrics->total_uncompressed_size, uncompressed_size);
        if (compressed_size > metrics->largest_compressed_size) metrics->largest_compressed_size = compressed_size;
        if (uncompressed_size > metrics->largest_uncompressed_size) metrics->largest_uncompressed_size = uncompressed_size;

        ratio = compressed_size == 0 ? (uncompressed_size == 0 ? 1.0 : (double)uncompressed_size)
                                     : (double)uncompressed_size / (double)compressed_size;
        if (ratio > metrics->maximum_entry_ratio) metrics->maximum_entry_ratio = ratio;

        if (is_absolute_path(name, filename_len)) metrics->absolute_path_count++;
        if (has_parent_traversal(name, filename_len)) metrics->path_traversal_count++;

        if (has_zip_extension(name, filename_len))
        {
            metrics->nested_archive_candidates++;
            if (method == 0)
            {
                inspect_stored_nested_zip(fp, local_offset, compressed_size, 1, metrics);
            }
        }

        free(variable);
        cursor += record_size;
    }

    metrics->aggregate_ratio = metrics->total_compressed_size == 0
        ? (metrics->total_uncompressed_size == 0 ? 1.0 : (double)metrics->total_uncompressed_size)
        : (double)metrics->total_uncompressed_size / (double)metrics->total_compressed_size;

    metrics->recommended_disk_budget = metrics->total_uncompressed_size;
    if (metrics->recommended_disk_budget < file_size) metrics->recommended_disk_budget = file_size;
    if (metrics->recommended_disk_budget <= UINT64_MAX / 5u)
    {
        metrics->recommended_disk_budget = metrics->recommended_disk_budget * 5u / 4u;
    }
    metrics->recommended_memory_budget = metrics->largest_uncompressed_size;
    if (metrics->recommended_memory_budget < (uint64_t)64 * 1024 * 1024)
    {
        metrics->recommended_memory_budget = (uint64_t)64 * 1024 * 1024;
    }
    if (metrics->recommended_memory_budget > (uint64_t)2 * 1024 * 1024 * 1024)
    {
        metrics->recommended_memory_budget = (uint64_t)2 * 1024 * 1024 * 1024;
    }

    metrics->central_directory_valid = 1;
    append_note(notes, notes_size, "ZIP metadata parsed without extracting compressed contents. ");
    if (metrics->nested_archive_candidates > metrics->nested_archives_inspected)
    {
        append_note(notes, notes_size, "Some nested archive candidates require decompression and were not opened by the metadata-only scanner. ");
    }
    return 0;
}

unsigned int af_score_zip(const AfZipMetrics *metrics, char *notes, size_t notes_size)
{
    unsigned int score = 0;
    if (metrics == NULL || !metrics->central_directory_valid)
    {
        append_note(notes, notes_size, "ZIP metadata could not be fully assessed. ");
        return 25;
    }
    if (metrics->aggregate_ratio >= 1000.0) { score += 45; append_note(notes, notes_size, "Extreme aggregate expansion ratio. "); }
    else if (metrics->aggregate_ratio >= 100.0) { score += 30; append_note(notes, notes_size, "High aggregate expansion ratio. "); }
    else if (metrics->aggregate_ratio >= 20.0) { score += 15; append_note(notes, notes_size, "Elevated aggregate expansion ratio. "); }

    if (metrics->maximum_entry_ratio >= 1000.0) { score += 25; append_note(notes, notes_size, "At least one entry has an extreme expansion ratio. "); }
    else if (metrics->maximum_entry_ratio >= 100.0) { score += 15; append_note(notes, notes_size, "At least one entry has a high expansion ratio. "); }
    else if (metrics->maximum_entry_ratio >= 20.0) { score += 8; append_note(notes, notes_size, "At least one entry has an elevated expansion ratio. "); }

    if (metrics->total_uncompressed_size >= (uint64_t)8 * 1024 * 1024 * 1024) { score += 30; append_note(notes, notes_size, "Declared expanded size is at least 8 GiB. "); }
    else if (metrics->total_uncompressed_size >= (uint64_t)1 * 1024 * 1024 * 1024) { score += 20; append_note(notes, notes_size, "Declared expanded size is at least 1 GiB. "); }
    else if (metrics->total_uncompressed_size >= (uint64_t)256 * 1024 * 1024) { score += 10; append_note(notes, notes_size, "Declared expanded size is at least 256 MiB. "); }

    if (metrics->entry_count >= 100000) { score += 20; append_note(notes, notes_size, "Very high archive entry count. "); }
    else if (metrics->entry_count >= 10000) { score += 12; append_note(notes, notes_size, "High archive entry count. "); }
    else if (metrics->entry_count >= 1000) { score += 6; append_note(notes, notes_size, "Elevated archive entry count. "); }

    if (metrics->nested_archive_candidates >= 16) { score += 15; append_note(notes, notes_size, "Many nested archive candidates. "); }
    else if (metrics->nested_archive_candidates > 0) { score += 5; append_note(notes, notes_size, "Nested archive content detected. "); }
    if (metrics->path_traversal_count > 0) { score += 25; append_note(notes, notes_size, "Parent-directory traversal paths detected. "); }
    if (metrics->absolute_path_count > 0) { score += 20; append_note(notes, notes_size, "Absolute extraction paths detected. "); }
    if (metrics->recursion_limit_hit) { score += 10; append_note(notes, notes_size, "Nested inspection safety limit reached. "); }

    return score > 100 ? 100 : score;
}
