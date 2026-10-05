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

static int write_single_entry_zip(const char *path, const char *name,
                                  unsigned long compressed_size,
                                  unsigned long uncompressed_size,
                                  const unsigned char *payload)
{
    unsigned int name_len = (unsigned int)strlen(name);
    unsigned long local_offset = 0;
    unsigned long cdir_offset;
    unsigned long cdir_end;
    FILE *fp = fopen(path, "wb");
    unsigned long i;
    if (fp == NULL) return -1;

    put_u32_le(fp, 0x04034b50ul);
    put_u16_le(fp, 20); put_u16_le(fp, 0); put_u16_le(fp, 0);
    put_u16_le(fp, 0); put_u16_le(fp, 0); put_u32_le(fp, 0);
    put_u32_le(fp, compressed_size); put_u32_le(fp, uncompressed_size);
    put_u16_le(fp, name_len); put_u16_le(fp, 0);
    fwrite(name, 1, name_len, fp);
    for (i = 0; i < compressed_size; i++) fputc(payload != NULL ? payload[i] : 'A', fp);

    cdir_offset = (unsigned long)ftell(fp);
    put_u32_le(fp, 0x02014b50ul);
    put_u16_le(fp, 20); put_u16_le(fp, 20); put_u16_le(fp, 0); put_u16_le(fp, 0);
    put_u16_le(fp, 0); put_u16_le(fp, 0); put_u32_le(fp, 0);
    put_u32_le(fp, compressed_size); put_u32_le(fp, uncompressed_size);
    put_u16_le(fp, name_len); put_u16_le(fp, 0); put_u16_le(fp, 0);
    put_u16_le(fp, 0); put_u16_le(fp, 0); put_u32_le(fp, 0); put_u32_le(fp, local_offset);
    fwrite(name, 1, name_len, fp);
    cdir_end = (unsigned long)ftell(fp);

    put_u32_le(fp, 0x06054b50ul);
    put_u16_le(fp, 0); put_u16_le(fp, 0); put_u16_le(fp, 1); put_u16_le(fp, 1);
    put_u32_le(fp, cdir_end - cdir_offset); put_u32_le(fp, cdir_offset); put_u16_le(fp, 0);
    fclose(fp);
    return 0;
}

static int write_pdf(const char *path, int high_cost)
{
    FILE *fp = fopen(path, "wb");
    if (fp == NULL) return -1;
    fputs("%PDF-1.7\n", fp);
    fputs("1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n", fp);
    fputs("2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 >>\nendobj\n", fp);
    fputs("3 0 obj\n<< /Type /Page /Resources << /XObject << /Im1 4 0 R >> >> >>\nendobj\n", fp);
    if (high_cost)
    {
        fputs("4 0 obj\n<< /Type /XObject /Subtype /Image /Width 50000 /Height 50000 ", fp);
        fputs("/ColorSpace /DeviceRGB /BitsPerComponent 8 /Length 900000000 ", fp);
        fputs("/Filter [/FlateDecode /ASCII85Decode /FlateDecode /ASCIIHexDecode] >>\n", fp);
    }
    else
    {
        fputs("4 0 obj\n<< /Type /XObject /Subtype /Image /Width 100 /Height 100 ", fp);
        fputs("/ColorSpace /DeviceRGB /BitsPerComponent 8 /Length 4 /Filter /FlateDecode >>\n", fp);
    }
    fputs("stream\nABCD\nendstream\nendobj\n", fp);
    fputs("xref\n0 5\n0000000000 65535 f \n", fp);
    fputs("trailer\n<< /Size 5 /Root 1 0 R >>\nstartxref\n0\n%%EOF\n", fp);
    fclose(fp);
    return 0;
}

int main(void)
{
    const unsigned char zip_header[] = {'P','K',3,4,0};
    const unsigned char pdf_header[] = {'%','P','D','F','-','1','.','7'};
    const unsigned char unknown[] = {'N','O','P','E'};
    const unsigned char nested_sig[] = {'P','K',3,4};
    AfReport report;

    assert(af_detect_type(zip_header, sizeof(zip_header)) == AF_TYPE_ZIP);
    assert(af_detect_type(pdf_header, sizeof(pdf_header)) == AF_TYPE_PDF);
    assert(af_detect_type(unknown, sizeof(unknown)) == AF_TYPE_UNKNOWN);
    assert(af_score_to_level(0) == AF_RISK_LOW);
    assert(af_score_to_level(30) == AF_RISK_MEDIUM);
    assert(af_score_to_level(60) == AF_RISK_HIGH);
    assert(af_score_to_level(80) == AF_RISK_CRITICAL);

    assert(write_single_entry_zip("af_normal.zip", "sample.bin", 100, 100, NULL) == 0);
    assert(af_scan_file("af_normal.zip", &report) == 0);
    assert(report.zip.central_directory_valid == 1);
    assert(report.zip.entry_count == 1);
    assert(report.zip.aggregate_ratio == 1.0);
    assert(report.score == 0);
    remove("af_normal.zip");

    assert(write_single_entry_zip("af_ratio.zip", "sample.bin", 1, 5000, NULL) == 0);
    assert(af_scan_file("af_ratio.zip", &report) == 0);
    assert(report.zip.aggregate_ratio >= 5000.0);
    assert(report.score >= 60);
    remove("af_ratio.zip");

    assert(write_single_entry_zip("af_traversal.zip", "../escape.txt", 4, 4, NULL) == 0);
    assert(af_scan_file("af_traversal.zip", &report) == 0);
    assert(report.zip.path_traversal_count == 1);
    remove("af_traversal.zip");

    assert(write_single_entry_zip("af_absolute.zip", "/tmp/escape.txt", 4, 4, NULL) == 0);
    assert(af_scan_file("af_absolute.zip", &report) == 0);
    assert(report.zip.absolute_path_count == 1);
    remove("af_absolute.zip");

    assert(write_single_entry_zip("af_nested.zip", "child.zip", 4, 4, nested_sig) == 0);
    assert(af_scan_file("af_nested.zip", &report) == 0);
    assert(report.zip.nested_archive_candidates == 1);
    assert(report.zip.nested_archives_inspected == 1);
    remove("af_nested.zip");

    assert(write_pdf("af_normal.pdf", 0) == 0);
    assert(af_scan_file("af_normal.pdf", &report) == 0);
    assert(report.type == AF_TYPE_PDF);
    assert(report.pdf.object_count >= 4);
    assert(report.pdf.stream_count == 1);
    assert(report.pdf.image_count == 1);
    assert(report.pdf.maximum_declared_pixels == 10000);
    assert(report.pdf.startxref_present == 1);
    assert(report.pdf.eof_marker_present == 1);
    assert(report.score < 30);
    remove("af_normal.pdf");

    /* Bounded metadata fixture: extreme declared work, tiny actual stream. */
    assert(write_pdf("af_pressure.pdf", 1) == 0);
    assert(af_scan_file("af_pressure.pdf", &report) == 0);
    assert(report.pdf.maximum_declared_pixels == 2500000000ull);
    assert(report.pdf.maximum_filter_chain >= 4);
    assert(report.pdf.declared_stream_ratio > 1000.0);
    assert(report.score >= 80);
    remove("af_pressure.pdf");

    puts("All AttendantForge v0.4 tests passed.");
    return 0;
}
