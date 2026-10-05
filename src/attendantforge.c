#include "attendantforge.h"
#include "pdf_analyzer.h"
#include "zip_analyzer.h"

#include <stdio.h>
#include <string.h>

static uint64_t get_file_size(FILE *fp)
{
    long end;
    if (fseek(fp, 0, SEEK_END) != 0) return 0;
    end = ftell(fp);
    if (end < 0) return 0;
    if (fseek(fp, 0, SEEK_SET) != 0) return 0;
    return (uint64_t)end;
}

static void append_note(char *notes, size_t notes_size, const char *text)
{
    size_t used;
    if (notes == NULL || notes_size == 0 || text == NULL) return;
    used = strlen(notes);
    if (used < notes_size - 1) strncat(notes, text, notes_size - used - 1);
}

AfFileType af_detect_type(const unsigned char *header, size_t len)
{
    if (header == NULL) return AF_TYPE_UNKNOWN;
    if (len >= 4 && header[0] == 'P' && header[1] == 'K' &&
        (header[2] == 3 || header[2] == 5 || header[2] == 7) &&
        (header[3] == 4 || header[3] == 6 || header[3] == 8)) return AF_TYPE_ZIP;
    if (len >= 5 && memcmp(header, "%PDF-", 5) == 0) return AF_TYPE_PDF;
    return AF_TYPE_UNKNOWN;
}

const char *af_type_name(AfFileType type)
{
    switch (type)
    {
        case AF_TYPE_ZIP: return "ZIP";
        case AF_TYPE_PDF: return "PDF";
        default: return "UNKNOWN";
    }
}

const char *af_risk_name(AfRiskLevel level)
{
    switch (level)
    {
        case AF_RISK_LOW: return "LOW";
        case AF_RISK_MEDIUM: return "MEDIUM";
        case AF_RISK_HIGH: return "HIGH";
        case AF_RISK_CRITICAL: return "CRITICAL";
        default: return "UNKNOWN";
    }
}

AfRiskLevel af_score_to_level(unsigned int score)
{
    if (score >= 80) return AF_RISK_CRITICAL;
    if (score >= 60) return AF_RISK_HIGH;
    if (score >= 30) return AF_RISK_MEDIUM;
    return AF_RISK_LOW;
}

int af_scan_file(const char *path, AfReport *report)
{
    FILE *fp;
    unsigned char header[16] = {0};
    size_t read_count;
    unsigned int score = 0;

    if (path == NULL || report == NULL) return -1;
    memset(report, 0, sizeof(*report));
    report->path = path;
    fp = fopen(path, "rb");
    if (fp == NULL) return -2;

    report->file_size = get_file_size(fp);
    read_count = fread(header, 1, sizeof(header), fp);
    report->type = af_detect_type(header, read_count);

    if (report->file_size > (uint64_t)1024 * 1024 * 1024)
    {
        score += 30;
        append_note(report->notes, sizeof(report->notes), "Very large input file. ");
    }
    else if (report->file_size > (uint64_t)100 * 1024 * 1024)
    {
        score += 15;
        append_note(report->notes, sizeof(report->notes), "Large input file. ");
    }

    if (report->type == AF_TYPE_ZIP)
    {
        int zip_rc = af_analyze_zip(fp, report->file_size, &report->zip, report->notes, sizeof(report->notes));
        score += zip_rc == 0 ? af_score_zip(&report->zip, report->notes, sizeof(report->notes)) : 25;
    }
    else if (report->type == AF_TYPE_PDF)
    {
        int pdf_rc = af_analyze_pdf(fp, report->file_size, &report->pdf, report->notes, sizeof(report->notes));
        score += pdf_rc == 0 ? af_score_pdf(&report->pdf, report->file_size, report->notes, sizeof(report->notes)) : 25;
    }
    else
    {
        score += 10;
        append_note(report->notes, sizeof(report->notes), "Unrecognized or unsupported signature. ");
    }

    fclose(fp);
    if (score > 100) score = 100;
    report->score = score;
    report->level = af_score_to_level(score);
    return 0;
}
