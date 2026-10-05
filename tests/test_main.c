#include "attendantforge.h"

#include <assert.h>
#include <stdio.h>
#include <string.h>

static void put_u16_le(FILE *fp, unsigned int value)
{
    fputc((int)(value & 0xffu), fp);
    fputc((int)((value >> 8) & 0xffu), fp);
}

static void put_u32_le(FILE *fp, unsigned long value)
{
    fputc((int)(value & 0xfful), fp);
    fputc((int)((value >> 8) & 0xfful), fp);
    fputc((int)((value >> 16) & 0xfful), fp);
    fputc((int)((value >> 24) & 0xfful), fp);
}

static int write_test_zip(const char *path, unsigned long compressed_size, unsigned long uncompressed_size)
{
    const char *name = "sample.bin";
    unsigned int name_len = (unsigned int)strlen(name);
    unsigned long local_offset = 0;
    unsigned long cdir_offset;
    unsigned long cdir_end;
    FILE *fp = fopen(path, "wb");
    unsigned long i;

    if (fp == NULL)
    {
        return -1;
    }

    /* Local file header. Method 0 is enough for parser tests; payload length is bounded. */
    put_u32_le(fp, 0x04034b50ul);
    put_u16_le(fp, 20);
    put_u16_le(fp, 0);
    put_u16_le(fp, 0);
    put_u16_le(fp, 0);
    put_u16_le(fp, 0);
    put_u32_le(fp, 0);
    put_u32_le(fp, compressed_size);
    put_u32_le(fp, uncompressed_size);
    put_u16_le(fp, name_len);
    put_u16_le(fp, 0);
    fwrite(name, 1, name_len, fp);
    for (i = 0; i < compressed_size; i++)
    {
        fputc('A', fp);
    }

    cdir_offset = (unsigned long)ftell(fp);
    put_u32_le(fp, 0x02014b50ul);
    put_u16_le(fp, 20);
    put_u16_le(fp, 20);
    put_u16_le(fp, 0);
    put_u16_le(fp, 0);
    put_u16_le(fp, 0);
    put_u16_le(fp, 0);
    put_u32_le(fp, 0);
    put_u32_le(fp, compressed_size);
    put_u32_le(fp, uncompressed_size);
    put_u16_le(fp, name_len);
    put_u16_le(fp, 0);
    put_u16_le(fp, 0);
    put_u16_le(fp, 0);
    put_u16_le(fp, 0);
    put_u32_le(fp, 0);
    put_u32_le(fp, local_offset);
    fwrite(name, 1, name_len, fp);
    cdir_end = (unsigned long)ftell(fp);

    put_u32_le(fp, 0x06054b50ul);
    put_u16_le(fp, 0);
    put_u16_le(fp, 0);
    put_u16_le(fp, 1);
    put_u16_le(fp, 1);
    put_u32_le(fp, cdir_end - cdir_offset);
    put_u32_le(fp, cdir_offset);
    put_u16_le(fp, 0);

    fclose(fp);
    return 0;
}

int main(void)
{
    const unsigned char zip_header[] = {'P','K',3,4,0};
    const unsigned char pdf_header[] = {'%','P','D','F','-','1','.','7'};
    const unsigned char unknown[] = {'N','O','P','E'};
    const char *normal_path = "af_test_normal.zip";
    const char *high_ratio_path = "af_test_high_ratio.zip";
    AfReport report;

    assert(af_detect_type(zip_header, sizeof(zip_header)) == AF_TYPE_ZIP);
    assert(af_detect_type(pdf_header, sizeof(pdf_header)) == AF_TYPE_PDF);
    assert(af_detect_type(unknown, sizeof(unknown)) == AF_TYPE_UNKNOWN);

    assert(af_score_to_level(0) == AF_RISK_LOW);
    assert(af_score_to_level(30) == AF_RISK_MEDIUM);
    assert(af_score_to_level(60) == AF_RISK_HIGH);
    assert(af_score_to_level(80) == AF_RISK_CRITICAL);

    assert(write_test_zip(normal_path, 100, 100) == 0);
    assert(af_scan_file(normal_path, &report) == 0);
    assert(report.type == AF_TYPE_ZIP);
    assert(report.zip.central_directory_valid == 1);
    assert(report.zip.entry_count == 1);
    assert(report.zip.total_compressed_size == 100);
    assert(report.zip.total_uncompressed_size == 100);
    assert(report.zip.aggregate_ratio == 1.0);
    assert(report.score == 0);
    remove(normal_path);

    /* Metadata-only bounded fixture: it declares a large ratio but does not contain a destructive payload. */
    assert(write_test_zip(high_ratio_path, 1, 5000) == 0);
    assert(af_scan_file(high_ratio_path, &report) == 0);
    assert(report.zip.central_directory_valid == 1);
    assert(report.zip.aggregate_ratio >= 5000.0);
    assert(report.score >= 60);
    remove(high_ratio_path);

    puts("All AttendantForge v0.2 tests passed.");
    return 0;
}
