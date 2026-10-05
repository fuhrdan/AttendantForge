#include "attendantforge.h"
#include "probe.h"
#include "policy.h"

#ifdef NDEBUG
#undef NDEBUG
#endif
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
    long xref_offset;
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
    xref_offset = ftell(fp);
    fputs("xref\n0 5\n0000000000 65535 f \n", fp);
    fputs("trailer\n<< /Size 5 /Root 1 0 R >>\nstartxref\n", fp);
    fprintf(fp, "%ld\n%%%%EOF\n", xref_offset);
    fclose(fp);
    return 0;
}

static int write_broken_reference_pdf(const char *path)
{
    long xref_offset;
    FILE *fp = fopen(path, "wb");
    if (fp == NULL) return -1;
    fputs("%PDF-1.7\n1 0 obj\n<< /Type /Catalog /Pages 999 0 R >>\nendobj\n", fp);
    xref_offset = ftell(fp);
    fputs("xref\n0 2\n0000000000 65535 f \ntrailer\n<< /Size 2 /Root 1 0 R >>\nstartxref\n", fp);
    fprintf(fp, "%ld\n%%%%EOF\n", xref_offset);
    fclose(fp);
    return 0;
}


static int write_xref_stream_pdf(const char *path)
{
    long xref_object_offset;
    FILE *fp = fopen(path, "wb");
    if (fp == NULL) return -1;
    fputs("%PDF-1.7\n", fp);
    fputs("1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n", fp);
    fputs("2 0 obj\n<< /Type /Pages /Kids [] /Count 0 >>\nendobj\n", fp);
    fputs("3 0 obj\n<< /Type /ObjStm /N 1 /First 4 /Length 4 >>\nstream\nABCD\nendstream\nendobj\n", fp);
    xref_object_offset = ftell(fp);
    fputs("4 0 obj\n<< /Type /XRef /Size 5 /W [1 2 1] /Length 4 >>\nstream\nABCD\nendstream\nendobj\n", fp);
    fputs("startxref\n", fp);
    fprintf(fp, "%ld\n%%%%EOF\n", xref_object_offset);
    fclose(fp);
    return 0;
}

static int write_policy(const char *path)
{
    FILE *fp = fopen(path, "w");
    if (fp == NULL) return -1;
    fputs("profile=upload-server\nwarn_score=40\nblock_score=65\nstrict=false\nallow_formats=ZIP,PDF,PNG\ndeny_formats=PDF\n", fp);
    fclose(fp);
    return 0;
}


static int write_gzip_metadata_fixture(const char *path, unsigned long declared_size)
{
    unsigned char h[10] = {0x1f,0x8b,8,0,0,0,0,0,0,3};
    FILE *fp = fopen(path, "wb");
    if (fp == NULL) return -1;
    fwrite(h,1,10,fp);
    fputc(0,fp); fputc(0,fp);
    put_u32_le(fp, 0);
    put_u32_le(fp, declared_size);
    fclose(fp);
    return 0;
}

static int write_tar_fixture(const char *path, const char *name, unsigned long size)
{
    unsigned char h[512] = {0};
    char oct[16];
    FILE *fp = fopen(path, "wb");
    unsigned long padded, i;
    if (fp == NULL) return -1;
    snprintf((char*)h, 100, "%s", name);
    snprintf(oct, sizeof(oct), "%011lo", size);
    memcpy(h+124, oct, 11); h[135] = '\0';
    h[156] = '0'; memcpy(h+257,"ustar",5);
    fwrite(h,1,512,fp);
    padded = (size + 511ul) & ~511ul;
    for (i=0;i<padded;i++) fputc(0,fp);
    memset(h,0,sizeof(h)); fwrite(h,1,512,fp); fwrite(h,1,512,fp);
    fclose(fp); return 0;
}

static int write_png_fixture(const char *path, unsigned long w, unsigned long hgt)
{
    unsigned char b[29] = {0x89,'P','N','G','\r','\n',0x1a,'\n',0,0,0,13,'I','H','D','R'};
    FILE *fp = fopen(path,"wb"); if(!fp) return -1;
    b[16]=(w>>24)&255; b[17]=(w>>16)&255; b[18]=(w>>8)&255; b[19]=w&255;
    b[20]=(hgt>>24)&255; b[21]=(hgt>>16)&255; b[22]=(hgt>>8)&255; b[23]=hgt&255;
    b[24]=8; b[25]=6; fwrite(b,1,sizeof(b),fp); fclose(fp); return 0;
}

static int write_jpeg_fixture(const char *path, unsigned int w, unsigned int hgt)
{
    unsigned char b[] = {0xff,0xd8,0xff,0xc0,0x00,0x11,8,0,0,0,0,3,1,0x11,0,2,0x11,0,3,0x11,0,0xff,0xd9};
    FILE *fp=fopen(path,"wb"); if(!fp) return -1;
    b[7]=(hgt>>8)&255; b[8]=hgt&255; b[9]=(w>>8)&255; b[10]=w&255;
    fwrite(b,1,sizeof(b),fp); fclose(fp); return 0;
}

static void test_probe_defaults(void)
{
    AfProbeLimits limits;
    af_probe_default_limits(&limits);
    assert(limits.memory_bytes == 256ull * 1024ull * 1024ull);
    assert(limits.cpu_seconds == 2u);
    assert(limits.timeout_ms == 3000u);
    assert(strcmp(af_probe_status_name(AF_PROBE_OK), "OK") == 0);
    assert(strcmp(af_probe_status_name(AF_PROBE_LIMIT_HIT), "LIMIT_HIT") == 0);
}
int main(void)
{
    assert(strcmp(AF_VERSION, "1.0.0") == 0);
    assert(strcmp(AF_TELEMETRY_SCHEMA, "1.0") == 0);
    assert(strcmp(AF_CLI_CONTRACT, "1.0") == 0);
    test_probe_defaults();
    const unsigned char zip_header[] = {'P','K',3,4,0};
    const unsigned char pdf_header[] = {'%','P','D','F','-','1','.','7'};
    const unsigned char unknown[] = {'N','O','P','E'};
    const unsigned char gz_header[] = {0x1f,0x8b,8,0};
    const unsigned char png_header[] = {0x89,'P','N','G','\r','\n',0x1a,'\n'};
    const unsigned char jpg_header[] = {0xff,0xd8,0xff,0xe0};
    const unsigned char nested_sig[] = {'P','K',3,4};
    AfReport report;
    AfPolicy policy;
    char policy_error[256] = {0};

    assert(af_detect_type(zip_header, sizeof(zip_header)) == AF_TYPE_ZIP);
    assert(af_detect_type(pdf_header, sizeof(pdf_header)) == AF_TYPE_PDF);
    assert(af_detect_type(unknown, sizeof(unknown)) == AF_TYPE_UNKNOWN);
    assert(af_detect_type(gz_header, sizeof(gz_header)) == AF_TYPE_GZIP);
    assert(af_detect_type(png_header, sizeof(png_header)) == AF_TYPE_PNG);
    assert(af_detect_type(jpg_header, sizeof(jpg_header)) == AF_TYPE_JPEG);
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
    assert(report.pdf.startxref_offset_valid == 1);
    assert(report.pdf.startxref_points_to_xref == 1);
    assert(report.pdf.unresolved_reference_count == 0);
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

    assert(write_broken_reference_pdf("af_broken_ref.pdf") == 0);
    assert(af_scan_file("af_broken_ref.pdf", &report) == 0);
    assert(report.pdf.indirect_reference_count >= 2);
    assert(report.pdf.unresolved_reference_count >= 1);
    assert(report.score >= 5);
    remove("af_broken_ref.pdf");

    assert(write_xref_stream_pdf("af_xref_stream.pdf") == 0);
    assert(af_scan_file("af_xref_stream.pdf", &report) == 0);
    assert(report.pdf.xref_stream_count >= 1);
    assert(report.pdf.object_stream_count >= 1);
    assert(report.pdf.startxref_points_to_xref_stream == 1);
    remove("af_xref_stream.pdf");

    assert(write_gzip_metadata_fixture("af_ratio.gz", 1000000ul) == 0);
    assert(af_scan_file("af_ratio.gz", &report) == 0);
    assert(report.type == AF_TYPE_GZIP);
    assert(report.gzip.declared_uncompressed_bytes == 1000000ul);
    assert(report.gzip.expansion_ratio > 1000.0);
    remove("af_ratio.gz");

    assert(write_tar_fixture("af_safe.tar", "sample.txt", 32) == 0);
    assert(af_scan_file("af_safe.tar", &report) == 0);
    assert(report.type == AF_TYPE_TAR);
    assert(report.tar.entry_count == 1);
    assert(report.tar.total_declared_bytes == 32);
    remove("af_safe.tar");

    assert(write_tar_fixture("af_traversal.tar", "../escape.txt", 1) == 0);
    assert(af_scan_file("af_traversal.tar", &report) == 0);
    assert(report.tar.path_traversal_count == 1);
    remove("af_traversal.tar");

    assert(write_png_fixture("af_large.png", 30000, 20000) == 0);
    assert(af_scan_file("af_large.png", &report) == 0);
    assert(report.type == AF_TYPE_PNG);
    assert(report.image.pixel_count == 600000000ull);
    assert(report.score >= 60);
    remove("af_large.png");

    assert(write_jpeg_fixture("af_image.jpg", 4000, 3000) == 0);
    assert(af_scan_file("af_image.jpg", &report) == 0);
    assert(report.type == AF_TYPE_JPEG);
    assert(report.image.pixel_count == 12000000ull);
    remove("af_image.jpg");

    af_policy_defaults(&policy);
    assert(strcmp(policy.profile, "desktop") == 0);
    assert(af_policy_apply_profile(&policy, "high-security", policy_error, sizeof(policy_error)) == 0);
    assert(policy.warn_score == 30 && policy.block_score == 60 && policy.strict == 1);
    assert(write_policy("af_policy.conf") == 0);
    assert(af_policy_load_file(&policy, "af_policy.conf", policy_error, sizeof(policy_error)) == 0);
    assert(strcmp(policy.profile, "upload-server") == 0);
    assert(policy.warn_score == 40 && policy.block_score == 65);
    assert(af_policy_format_allowed(&policy, AF_TYPE_ZIP) == 1);
    assert(af_policy_format_allowed(&policy, AF_TYPE_PDF) == 0);
    assert(af_policy_format_allowed(&policy, AF_TYPE_GZIP) == 0);
    remove("af_policy.conf");


    assert(write_png_fixture("af_disguised.pdf", 64, 64) == 0);
    assert(af_scan_file("af_disguised.pdf", &report) == 0);
    assert(report.type == AF_TYPE_PNG);
    assert(report.extension_signature_mismatch == 1);
    remove("af_disguised.pdf");

    af_policy_defaults(&policy);
    policy.deny_formats = AF_FORMAT_BIT(AF_TYPE_PDF);
    assert(af_policy_format_allowed(&policy, AF_TYPE_PDF) == 0);
    assert(af_policy_format_allowed(&policy, AF_TYPE_ZIP) == 1);

    puts("All AttendantForge v1.0.0 tests passed.");
    return 0;
}
