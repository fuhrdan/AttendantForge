#include "pdf_analyzer.h"

#include <ctype.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>

#define AF_PDF_ANALYSIS_LIMIT (64u * 1024u * 1024u)
#define AF_PDF_IMAGE_WINDOW   4096u

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

static int is_delim(unsigned char c)
{
    return isspace(c) || c == '<' || c == '>' || c == '[' || c == ']' ||
           c == '(' || c == ')' || c == '/' || c == '%';
}

static int match_token(const unsigned char *data, size_t len, size_t pos, const char *token)
{
    size_t tlen = strlen(token);
    if (pos + tlen > len || memcmp(data + pos, token, tlen) != 0)
    {
        return 0;
    }
    if (pos > 0 && !is_delim(data[pos - 1]))
    {
        return 0;
    }
    if (pos + tlen < len && !is_delim(data[pos + tlen]))
    {
        return 0;
    }
    return 1;
}

static uint64_t saturating_add(uint64_t a, uint64_t b)
{
    return UINT64_MAX - a < b ? UINT64_MAX : a + b;
}

static uint64_t saturating_mul(uint64_t a, uint64_t b)
{
    if (a == 0 || b == 0)
    {
        return 0;
    }
    return a > UINT64_MAX / b ? UINT64_MAX : a * b;
}

static int parse_uint_after_key(const unsigned char *data, size_t len, size_t start,
                                const char *key, uint64_t *value)
{
    size_t key_len = strlen(key);
    size_t i;
    size_t end = start + AF_PDF_IMAGE_WINDOW;
    if (end > len)
    {
        end = len;
    }

    for (i = start; i + key_len < end; i++)
    {
        if (memcmp(data + i, key, key_len) == 0)
        {
            size_t p = i + key_len;
            uint64_t v = 0;
            int found = 0;
            while (p < end && isspace(data[p])) p++;
            while (p < end && isdigit(data[p]))
            {
                unsigned int digit = (unsigned int)(data[p] - '0');
                if (v > (UINT64_MAX - digit) / 10u)
                {
                    v = UINT64_MAX;
                }
                else
                {
                    v = v * 10u + digit;
                }
                found = 1;
                p++;
            }
            if (found)
            {
                *value = v;
                return 1;
            }
        }
    }
    return 0;
}

static unsigned int count_filter_chain(const unsigned char *data, size_t len, size_t pos)
{
    size_t i = pos;
    size_t end = pos + 512u;
    unsigned int count = 0;
    int in_array = 0;
    if (end > len) end = len;
    while (i < end && data[i] != '/' && data[i] != '[' && data[i] != '\n' && data[i] != '\r') i++;
    if (i < end && data[i] == '[')
    {
        in_array = 1;
        i++;
    }
    while (i < end)
    {
        if (in_array && data[i] == ']') break;
        if (!in_array && (data[i] == '\n' || data[i] == '\r' || data[i] == '>')) break;
        if (data[i] == '/')
        {
            count++;
            i++;
            while (i < end && !isspace(data[i]) && data[i] != '/' && data[i] != ']') i++;
            if (!in_array) break;
            continue;
        }
        i++;
    }
    return count;
}

static int looks_like_obj(const unsigned char *data, size_t len, size_t pos)
{
    size_t p = pos;
    int first = 0;
    int second = 0;
    while (p < len && isspace(data[p])) p++;
    while (p < len && isdigit(data[p])) { first = 1; p++; }
    if (!first) return 0;
    while (p < len && isspace(data[p])) p++;
    while (p < len && isdigit(data[p])) { second = 1; p++; }
    if (!second) return 0;
    while (p < len && isspace(data[p])) p++;
    return p + 3 <= len && memcmp(data + p, "obj", 3) == 0 &&
           (p + 3 == len || is_delim(data[p + 3]));
}


#define AF_PDF_OBJECT_TRACK_LIMIT 100000u

static int parse_uint_at(const unsigned char *data, size_t len, size_t *pos, uint64_t *value)
{
    uint64_t v = 0;
    int found = 0;
    size_t p = *pos;
    while (p < len && isspace(data[p])) p++;
    while (p < len && isdigit(data[p]))
    {
        unsigned int digit = (unsigned int)(data[p] - '0');
        v = v > (UINT64_MAX - digit) / 10u ? UINT64_MAX : v * 10u + digit;
        found = 1;
        p++;
    }
    if (!found) return 0;
    *value = v;
    *pos = p;
    return 1;
}

static int contains_u64(const uint64_t *items, size_t count, uint64_t value)
{
    size_t i;
    for (i = 0; i < count; i++) if (items[i] == value) return 1;
    return 0;
}

static int parse_object_header(const unsigned char *data, size_t len, size_t pos, uint64_t *object_number)
{
    size_t p = pos;
    uint64_t obj = 0, gen = 0;
    if (!parse_uint_at(data, len, &p, &obj)) return 0;
    if (!parse_uint_at(data, len, &p, &gen)) return 0;
    (void)gen;
    while (p < len && isspace(data[p])) p++;
    if (p + 3 > len || memcmp(data + p, "obj", 3) != 0) return 0;
    if (p + 3 < len && !is_delim(data[p + 3])) return 0;
    *object_number = obj;
    return 1;
}

static int parse_indirect_reference(const unsigned char *data, size_t len, size_t pos, uint64_t *object_number)
{
    size_t p = pos;
    uint64_t obj = 0, gen = 0;
    if (!parse_uint_at(data, len, &p, &obj)) return 0;
    if (!parse_uint_at(data, len, &p, &gen)) return 0;
    (void)gen;
    while (p < len && isspace(data[p])) p++;
    if (p >= len || data[p] != 'R') return 0;
    if (p + 1 < len && !is_delim(data[p + 1])) return 0;
    *object_number = obj;
    return 1;
}

static int parse_startxref_value(const unsigned char *data, size_t len, size_t pos, uint64_t *value)
{
    size_t p = pos + 9u;
    return parse_uint_at(data, len, &p, value);
}

static int object_at_offset_is_xref_stream(const unsigned char *data, size_t len, size_t offset)
{
    size_t end;
    size_t i;
    if (offset >= len || !looks_like_obj(data, len, offset)) return 0;
    end = offset + 4096u;
    if (end > len) end = len;
    for (i = offset; i + 11u <= end; i++)
    {
        if (memcmp(data + i, "/Type /XRef", 11u) == 0) return 1;
        if (i + 6u <= end && memcmp(data + i, "stream", 6u) == 0) break;
    }
    return 0;
}

int af_analyze_pdf(FILE *fp, uint64_t file_size, AfPdfMetrics *metrics, char *notes, size_t notes_size)
{
    size_t read_size;
    unsigned char *data;
    size_t got;
    size_t i;
    unsigned int depth = 0;
    uint64_t *objects = NULL;
    uint64_t *refs = NULL;
    size_t object_track_count = 0;
    size_t ref_track_count = 0;

    if (fp == NULL || metrics == NULL)
    {
        return -1;
    }
    memset(metrics, 0, sizeof(*metrics));

    read_size = file_size > AF_PDF_ANALYSIS_LIMIT ? AF_PDF_ANALYSIS_LIMIT : (size_t)file_size;
    data = (unsigned char *)malloc(read_size + 1u);
    if (data == NULL)
    {
        return -2;
    }
    objects = (uint64_t *)calloc(AF_PDF_OBJECT_TRACK_LIMIT, sizeof(uint64_t));
    refs = (uint64_t *)calloc(AF_PDF_OBJECT_TRACK_LIMIT, sizeof(uint64_t));
    if (objects == NULL || refs == NULL)
    {
        free(objects); free(refs); free(data);
        return -2;
    }
    if (fseek(fp, 0, SEEK_SET) != 0)
    {
        free(objects); free(refs); free(data);
        return -3;
    }
    got = fread(data, 1, read_size, fp);
    data[got] = 0;
    if (got < 5 || memcmp(data, "%PDF-", 5) != 0)
    {
        free(objects); free(refs); free(data);
        append_note(notes, notes_size, "PDF header is missing or malformed. ");
        return -4;
    }

    if ((uint64_t)got < file_size)
    {
        metrics->analysis_truncated = 1;
        append_note(notes, notes_size, "PDF static analysis was capped at 64 MiB. ");
    }

    for (i = 0; i < got; i++)
    {
        if (i + 1 < got && data[i] == '<' && data[i + 1] == '<')
        {
            depth++;
            if (depth > metrics->maximum_structure_depth) metrics->maximum_structure_depth = depth;
            i++;
            continue;
        }
        if (i + 1 < got && data[i] == '>' && data[i + 1] == '>')
        {
            if (depth > 0) depth--;
            i++;
            continue;
        }
        if (data[i] == '[')
        {
            depth++;
            if (depth > metrics->maximum_structure_depth) metrics->maximum_structure_depth = depth;
            continue;
        }
        if (data[i] == ']')
        {
            if (depth > 0) depth--;
            continue;
        }

        if (isdigit(data[i]) && (i == 0 || is_delim(data[i - 1])) && looks_like_obj(data, got, i))
        {
            uint64_t object_number = 0;
            metrics->object_count++;
            if (parse_object_header(data, got, i, &object_number) && object_track_count < AF_PDF_OBJECT_TRACK_LIMIT)
            {
                if (!contains_u64(objects, object_track_count, object_number)) objects[object_track_count++] = object_number;
            }
            while (i < got && !isspace(data[i])) i++;
            continue;
        }
        if (isdigit(data[i]) && (i == 0 || is_delim(data[i - 1])))
        {
            uint64_t ref_object = 0;
            if (parse_indirect_reference(data, got, i, &ref_object))
            {
                metrics->indirect_reference_count++;
                if (ref_track_count < AF_PDF_OBJECT_TRACK_LIMIT) refs[ref_track_count++] = ref_object;
            }
        }
        if (match_token(data, got, i, "stream"))
        {
            size_t p = i + 6;
            metrics->stream_count++;
            while (p + 9 <= got)
            {
                if (memcmp(data + p, "endstream", 9) == 0 &&
                    (p == 0 || is_delim(data[p - 1])) &&
                    (p + 9 == got || is_delim(data[p + 9])))
                {
                    i = p + 8;
                    break;
                }
                p++;
            }
            if (p + 9 > got)
            {
                i += 5;
            }
            continue;
        }
        if (match_token(data, got, i, "xref"))
        {
            metrics->xref_section_count++;
            i += 3;
            continue;
        }
        if (match_token(data, got, i, "startxref"))
        {
            uint64_t offset = 0;
            metrics->startxref_present = 1;
            if (parse_startxref_value(data, got, i, &offset))
            {
                metrics->startxref_offset = offset;
                if (offset < file_size) metrics->startxref_offset_valid = 1;
                if (offset + 4u <= got && memcmp(data + (size_t)offset, "xref", 4) == 0)
                    metrics->startxref_points_to_xref = 1;
                else if (offset < got && object_at_offset_is_xref_stream(data, got, (size_t)offset))
                    metrics->startxref_points_to_xref_stream = 1;
            }
            i += 8;
            continue;
        }
        if (i + 5 <= got && memcmp(data + i, "%%EOF", 5) == 0)
        {
            metrics->eof_marker_present = 1;
            i += 4;
            continue;
        }
        if (i + 7 <= got && memcmp(data + i, "/Filter", 7) == 0)
        {
            unsigned int chain = count_filter_chain(data, got, i + 7);
            metrics->filter_count++;
            if (chain > metrics->maximum_filter_chain) metrics->maximum_filter_chain = chain;
        }
        if (i + 12 <= got && memcmp(data + i, "/FlateDecode", 12) == 0)
        {
            metrics->flate_filter_count++;
        }
        if (i + 13 <= got && memcmp(data + i, "/EmbeddedFile", 13) == 0)
        {
            metrics->embedded_file_count++;
        }
        if (i + 11 <= got && memcmp(data + i, "/Type /XRef", 11) == 0)
        {
            metrics->xref_stream_count++;
        }
        if (i + 13 <= got && memcmp(data + i, "/Type /ObjStm", 13) == 0)
        {
            metrics->object_stream_count++;
        }
        if (i + 8 <= got && memcmp(data + i, "/XRefStm", 8) == 0)
        {
            metrics->xref_stream_reference_count++;
        }
        if (i + 5 <= got && memcmp(data + i, "/Prev", 5) == 0)
        {
            metrics->incremental_update_count++;
        }
        if (i + 7 <= got && memcmp(data + i, "/Length", 7) == 0)
        {
            uint64_t length_value = 0;
            if (parse_uint_after_key(data, got, i, "/Length", &length_value))
            {
                metrics->declared_stream_bytes = saturating_add(metrics->declared_stream_bytes, length_value);
            }
        }
        if (i + 15 <= got && memcmp(data + i, "/Subtype /Image", 15) == 0)
        {
            uint64_t width = 0;
            uint64_t height = 0;
            uint64_t pixels;
            metrics->image_count++;
            size_t image_start = i > 2048u ? i - 2048u : 0u;
            if (parse_uint_after_key(data, got, image_start, "/Width", &width) &&
                parse_uint_after_key(data, got, image_start, "/Height", &height))
            {
                pixels = saturating_mul(width, height);
                metrics->total_declared_pixels = saturating_add(metrics->total_declared_pixels, pixels);
                if (pixels > metrics->maximum_declared_pixels) metrics->maximum_declared_pixels = pixels;
            }
        }
    }

    {
        size_t r;
        for (r = 0; r < ref_track_count; r++)
            if (!contains_u64(objects, object_track_count, refs[r])) metrics->unresolved_reference_count++;
    }

    metrics->estimated_image_memory = saturating_mul(metrics->total_declared_pixels, 4u);
    metrics->declared_stream_ratio = file_size == 0 ? 0.0 : (double)metrics->declared_stream_bytes / (double)file_size;
    metrics->recommended_memory_budget = metrics->estimated_image_memory;
    if (metrics->recommended_memory_budget < (uint64_t)64 * 1024 * 1024)
    {
        metrics->recommended_memory_budget = (uint64_t)64 * 1024 * 1024;
    }
    if (metrics->recommended_memory_budget < metrics->declared_stream_bytes && metrics->declared_stream_bytes <= UINT64_MAX / 2u)
    {
        metrics->recommended_memory_budget = metrics->declared_stream_bytes * 2u;
    }
    if (metrics->recommended_memory_budget > (uint64_t)4 * 1024 * 1024 * 1024)
    {
        metrics->recommended_memory_budget = (uint64_t)4 * 1024 * 1024 * 1024;
    }

    if (metrics->startxref_present && !metrics->startxref_offset_valid)
        append_note(notes, notes_size, "startxref offset is outside the file. ");
    else if (metrics->startxref_present && !metrics->startxref_points_to_xref && !metrics->startxref_points_to_xref_stream)
        append_note(notes, notes_size, "startxref does not point to a recognized classic xref table or xref-stream object in the bounded scan. ");
    if (metrics->unresolved_reference_count > 0)
        append_note(notes, notes_size, "Unresolved indirect object references were observed. ");
    append_note(notes, notes_size, "PDF structure inspected statically without decoding streams or rendering pages. ");
    free(objects); free(refs); free(data);
    return 0;
}

unsigned int af_score_pdf(const AfPdfMetrics *metrics, uint64_t file_size, char *notes, size_t notes_size)
{
    unsigned int score = 0;
    (void)file_size;
    if (metrics == NULL)
    {
        return 25;
    }

    if (metrics->object_count >= 100000) { score += 25; append_note(notes, notes_size, "Very high PDF object count. "); }
    else if (metrics->object_count >= 20000) { score += 15; append_note(notes, notes_size, "High PDF object count. "); }
    else if (metrics->object_count >= 5000) { score += 8; append_note(notes, notes_size, "Elevated PDF object count. "); }

    if (metrics->stream_count >= 10000) { score += 20; append_note(notes, notes_size, "Very high PDF stream count. "); }
    else if (metrics->stream_count >= 2000) { score += 12; append_note(notes, notes_size, "High PDF stream count. "); }

    if (metrics->declared_stream_ratio >= 1000.0) { score += 35; append_note(notes, notes_size, "Extreme declared stream-to-file ratio. "); }
    else if (metrics->declared_stream_ratio >= 100.0) { score += 25; append_note(notes, notes_size, "High declared stream-to-file ratio. "); }
    else if (metrics->declared_stream_ratio >= 20.0) { score += 12; append_note(notes, notes_size, "Elevated declared stream-to-file ratio. "); }

    if (metrics->maximum_declared_pixels >= 1000000000ull) { score += 30; append_note(notes, notes_size, "At least one image declares at least one billion pixels. "); }
    else if (metrics->maximum_declared_pixels >= 250000000ull) { score += 20; append_note(notes, notes_size, "At least one image declares at least 250 million pixels. "); }
    else if (metrics->maximum_declared_pixels >= 100000000ull) { score += 12; append_note(notes, notes_size, "At least one image declares at least 100 million pixels. "); }

    if (metrics->total_declared_pixels >= 1000000000ull) { score += 20; append_note(notes, notes_size, "Aggregate image pixel workload is very high. "); }
    else if (metrics->total_declared_pixels >= 250000000ull) { score += 12; append_note(notes, notes_size, "Aggregate image pixel workload is high. "); }

    if (metrics->maximum_filter_chain >= 8) { score += 20; append_note(notes, notes_size, "Long PDF filter chain detected. "); }
    else if (metrics->maximum_filter_chain >= 4) { score += 10; append_note(notes, notes_size, "Elevated PDF filter-chain depth. "); }

    if (metrics->maximum_structure_depth >= 100) { score += 20; append_note(notes, notes_size, "Very deep PDF dictionary/array nesting. "); }
    else if (metrics->maximum_structure_depth >= 40) { score += 10; append_note(notes, notes_size, "Deep PDF dictionary/array nesting. "); }

    if (metrics->embedded_file_count >= 16) { score += 15; append_note(notes, notes_size, "Many embedded-file objects detected. "); }
    else if (metrics->embedded_file_count > 0) { score += 5; append_note(notes, notes_size, "Embedded-file content detected. "); }

    if (!metrics->startxref_present) { score += 5; append_note(notes, notes_size, "startxref marker was not observed. "); }
    else if (!metrics->startxref_offset_valid) { score += 12; append_note(notes, notes_size, "startxref offset is invalid. "); }
    else if (!metrics->startxref_points_to_xref && !metrics->startxref_points_to_xref_stream &&
             (metrics->xref_section_count > 0 || metrics->xref_stream_count > 0))
    {
        score += 8;
        append_note(notes, notes_size, "startxref did not resolve to an observed xref structure. ");
    }
    if (metrics->object_stream_count >= 10000) { score += 12; append_note(notes, notes_size, "Very high PDF object-stream count. "); }
    else if (metrics->object_stream_count >= 2000) { score += 6; append_note(notes, notes_size, "High PDF object-stream count. "); }
    if (metrics->incremental_update_count >= 1000) { score += 10; append_note(notes, notes_size, "Very high incremental-update chain count. "); }
    else if (metrics->incremental_update_count >= 100) { score += 5; append_note(notes, notes_size, "Large incremental-update chain count. "); }
    if (metrics->unresolved_reference_count >= 100) { score += 15; append_note(notes, notes_size, "Many unresolved PDF indirect references. "); }
    else if (metrics->unresolved_reference_count > 0) { score += 5; append_note(notes, notes_size, "Unresolved PDF indirect references detected. "); }
    if (!metrics->eof_marker_present) { score += 5; append_note(notes, notes_size, "PDF EOF marker was not observed. "); }
    if (metrics->analysis_truncated) { score += 5; append_note(notes, notes_size, "Risk estimate is based on a bounded prefix scan. "); }

    return score > 100 ? 100 : score;
}
