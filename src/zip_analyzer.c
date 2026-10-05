#include "zip_analyzer.h"

#include <limits.h>
#include <stdlib.h>
#include <string.h>

#define AF_ZIP_EOCD_SIGNATURE 0x06054b50u
#define AF_ZIP_CDIR_SIGNATURE 0x02014b50u
#define AF_ZIP_EOCD_MIN_SIZE 22u
#define AF_ZIP_MAX_COMMENT 65535u
#define AF_ZIP_CDIR_FIXED_SIZE 46u

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

static void append_note(char *notes, size_t notes_size, const char *text)
{
    size_t used;

    if (notes == NULL || notes_size == 0 || text == NULL)
    {
        return;
    }

    used = strlen(notes);
    if (used >= notes_size - 1)
    {
        return;
    }

    strncat(notes, text, notes_size - used - 1);
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

int af_analyze_zip(FILE *fp, uint64_t file_size, AfZipMetrics *metrics, char *notes, size_t notes_size)
{
    unsigned char eocd[AF_ZIP_EOCD_MIN_SIZE];
    uint64_t eocd_offset = 0;
    uint16_t disk_no;
    uint16_t cdir_disk_no;
    uint16_t entries_disk;
    uint16_t entries_total;
    uint32_t cdir_size;
    uint32_t cdir_offset;
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
    entries_disk = read_u16_le(eocd + 8);
    entries_total = read_u16_le(eocd + 10);
    cdir_size = read_u32_le(eocd + 12);
    cdir_offset = read_u32_le(eocd + 16);

    if (disk_no != 0 || cdir_disk_no != 0 || entries_disk != entries_total)
    {
        append_note(notes, notes_size, "Multi-disk ZIP archives are not supported in v0.2. ");
        return -3;
    }

    if (entries_total == 0xffffu || cdir_size == 0xffffffffu || cdir_offset == 0xffffffffu)
    {
        metrics->zip64_detected = 1;
        append_note(notes, notes_size, "ZIP64 metadata detected; full ZIP64 accounting is planned for a later release. ");
        return -4;
    }

    cdir_end = (uint64_t)cdir_offset + (uint64_t)cdir_size;
    if (cdir_end > eocd_offset || cdir_end > file_size)
    {
        append_note(notes, notes_size, "Central-directory bounds are inconsistent with file size. ");
        return -5;
    }

    cursor = cdir_offset;
    for (i = 0; i < entries_total; i++)
    {
        unsigned char fixed[AF_ZIP_CDIR_FIXED_SIZE];
        uint32_t compressed_size;
        uint32_t uncompressed_size;
        uint16_t filename_len;
        uint16_t extra_len;
        uint16_t comment_len;
        uint64_t record_size;
        double ratio;

        if (cursor + AF_ZIP_CDIR_FIXED_SIZE > cdir_end)
        {
            append_note(notes, notes_size, "Central directory ended before all declared entries were parsed. ");
            return -6;
        }

        if (read_exact(fp, cursor, fixed, sizeof(fixed)) != 0)
        {
            append_note(notes, notes_size, "Unable to read a central-directory entry. ");
            return -7;
        }

        if (read_u32_le(fixed) != AF_ZIP_CDIR_SIGNATURE)
        {
            append_note(notes, notes_size, "Invalid central-directory entry signature. ");
            return -8;
        }

        compressed_size = read_u32_le(fixed + 20);
        uncompressed_size = read_u32_le(fixed + 24);
        filename_len = read_u16_le(fixed + 28);
        extra_len = read_u16_le(fixed + 30);
        comment_len = read_u16_le(fixed + 32);

        if (compressed_size == 0xffffffffu || uncompressed_size == 0xffffffffu)
        {
            metrics->zip64_detected = 1;
            append_note(notes, notes_size, "ZIP64 entry metadata detected; full ZIP64 accounting is planned for a later release. ");
            return -4;
        }

        record_size = (uint64_t)AF_ZIP_CDIR_FIXED_SIZE + filename_len + extra_len + comment_len;
        if (cursor + record_size > cdir_end)
        {
            append_note(notes, notes_size, "Central-directory entry extends beyond declared directory bounds. ");
            return -9;
        }

        metrics->entry_count++;
        metrics->total_compressed_size += compressed_size;
        metrics->total_uncompressed_size += uncompressed_size;

        if (compressed_size > metrics->largest_compressed_size)
        {
            metrics->largest_compressed_size = compressed_size;
        }
        if (uncompressed_size > metrics->largest_uncompressed_size)
        {
            metrics->largest_uncompressed_size = uncompressed_size;
        }

        if (compressed_size == 0)
        {
            ratio = uncompressed_size == 0 ? 1.0 : (double)uncompressed_size;
        }
        else
        {
            ratio = (double)uncompressed_size / (double)compressed_size;
        }

        if (ratio > metrics->maximum_entry_ratio)
        {
            metrics->maximum_entry_ratio = ratio;
        }

        cursor += record_size;
    }

    if (metrics->total_compressed_size == 0)
    {
        metrics->aggregate_ratio = metrics->total_uncompressed_size == 0
            ? 1.0
            : (double)metrics->total_uncompressed_size;
    }
    else
    {
        metrics->aggregate_ratio = (double)metrics->total_uncompressed_size
            / (double)metrics->total_compressed_size;
    }

    metrics->central_directory_valid = 1;
    append_note(notes, notes_size, "ZIP central directory parsed without extracting file contents. ");
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

    if (metrics->aggregate_ratio >= 1000.0)
    {
        score += 45;
        append_note(notes, notes_size, "Extreme aggregate expansion ratio. ");
    }
    else if (metrics->aggregate_ratio >= 100.0)
    {
        score += 30;
        append_note(notes, notes_size, "High aggregate expansion ratio. ");
    }
    else if (metrics->aggregate_ratio >= 20.0)
    {
        score += 15;
        append_note(notes, notes_size, "Elevated aggregate expansion ratio. ");
    }

    if (metrics->maximum_entry_ratio >= 1000.0)
    {
        score += 25;
        append_note(notes, notes_size, "At least one entry has an extreme expansion ratio. ");
    }
    else if (metrics->maximum_entry_ratio >= 100.0)
    {
        score += 15;
        append_note(notes, notes_size, "At least one entry has a high expansion ratio. ");
    }
    else if (metrics->maximum_entry_ratio >= 20.0)
    {
        score += 8;
        append_note(notes, notes_size, "At least one entry has an elevated expansion ratio. ");
    }

    if (metrics->total_uncompressed_size >= (uint64_t)8 * 1024 * 1024 * 1024)
    {
        score += 30;
        append_note(notes, notes_size, "Declared expanded size is at least 8 GiB. ");
    }
    else if (metrics->total_uncompressed_size >= (uint64_t)1 * 1024 * 1024 * 1024)
    {
        score += 20;
        append_note(notes, notes_size, "Declared expanded size is at least 1 GiB. ");
    }
    else if (metrics->total_uncompressed_size >= (uint64_t)256 * 1024 * 1024)
    {
        score += 10;
        append_note(notes, notes_size, "Declared expanded size is at least 256 MiB. ");
    }

    if (metrics->entry_count >= 100000)
    {
        score += 20;
        append_note(notes, notes_size, "Very high archive entry count. ");
    }
    else if (metrics->entry_count >= 10000)
    {
        score += 12;
        append_note(notes, notes_size, "High archive entry count. ");
    }
    else if (metrics->entry_count >= 1000)
    {
        score += 6;
        append_note(notes, notes_size, "Elevated archive entry count. ");
    }

    if (score > 100)
    {
        score = 100;
    }

    return score;
}
