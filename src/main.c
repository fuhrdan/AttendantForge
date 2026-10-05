#include "attendantforge.h"

#include <stdio.h>
#include <string.h>

static void print_usage(const char *exe)
{
    printf("AttendantForge v%s\n", AF_VERSION);
    printf("Usage: %s scan <file>\n", exe);
    printf("       %s --version\n", exe);
}

static void print_report(const AfReport *report)
{
    double mib = (double)report->file_size / (1024.0 * 1024.0);

    printf("AttendantForge v%s\n\n", AF_VERSION);
    printf("File:        %s\n", report->path);
    printf("Type:        %s\n", af_type_name(report->type));
    printf("Size:        %.2f MiB\n", mib);
    printf("Risk score:  %u / 100\n", report->score);
    printf("Risk level:  %s\n", af_risk_name(report->level));
    printf("Notes:       %s\n", report->notes[0] ? report->notes : "None");

    if (report->type == AF_TYPE_ZIP)
    {
        printf("\nZIP deep analysis begins in v0.2.\n");
    }
    else if (report->type == AF_TYPE_PDF)
    {
        printf("\nPDF deep analysis begins in v0.4.\n");
    }
}

int main(int argc, char **argv)
{
    AfReport report;
    int rc;

    if (argc == 2 && strcmp(argv[1], "--version") == 0)
    {
        printf("%s\n", AF_VERSION);
        return 0;
    }

    if (argc != 3 || strcmp(argv[1], "scan") != 0)
    {
        print_usage(argv[0]);
        return 1;
    }

    rc = af_scan_file(argv[2], &report);
    if (rc != 0)
    {
        fprintf(stderr, "Unable to scan '%s' (error %d).\n", argv[2], rc);
        return 2;
    }

    print_report(&report);
    return 0;
}
