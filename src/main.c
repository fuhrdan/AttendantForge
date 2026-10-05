#include "attendantforge.h"

#include <stdio.h>
#include <string.h>

static void print_usage(const char *exe)
{
    printf("AttendantForge v%s\n", AF_VERSION);
    printf("Usage: %s scan <file>\n", exe);
    printf("       %s --version\n", exe);
}

static double to_mib(uint64_t bytes)
{
    return (double)bytes / (1024.0 * 1024.0);
}

static void print_report(const AfReport *report)
{
    printf("AttendantForge v%s\n\n", AF_VERSION);
    printf("File:        %s\n", report->path);
    printf("Type:        %s\n", af_type_name(report->type));
    printf("Size:        %.2f MiB\n", to_mib(report->file_size));

    if (report->type == AF_TYPE_ZIP)
    {
        printf("\nZIP resource metadata\n---------------------\n");
        printf("Entries:                    %llu\n", (unsigned long long)report->zip.entry_count);
        printf("Compressed payload:         %.2f MiB\n", to_mib(report->zip.total_compressed_size));
        printf("Declared expanded data:     %.2f MiB\n", to_mib(report->zip.total_uncompressed_size));
        printf("Aggregate ratio:            %.2fx\n", report->zip.aggregate_ratio);
        printf("Maximum entry ratio:        %.2fx\n", report->zip.maximum_entry_ratio);
        printf("Largest entry expanded:     %.2f MiB\n", to_mib(report->zip.largest_uncompressed_size));
        printf("Nested archive candidates:  %llu\n", (unsigned long long)report->zip.nested_archive_candidates);
        printf("Nested archives confirmed:  %llu\n", (unsigned long long)report->zip.nested_archives_inspected);
        printf("Maximum inspected depth:    %u\n", report->zip.maximum_nested_depth);
        printf("Traversal paths:            %llu\n", (unsigned long long)report->zip.path_traversal_count);
        printf("Absolute paths:             %llu\n", (unsigned long long)report->zip.absolute_path_count);
        printf("Recommended disk budget:    %.2f MiB\n", to_mib(report->zip.recommended_disk_budget));
        printf("Recommended memory budget:  %.2f MiB\n", to_mib(report->zip.recommended_memory_budget));
        printf("Central directory:          %s\n", report->zip.central_directory_valid ? "VALID" : "UNVERIFIED");
        if (report->zip.zip64_detected) printf("ZIP64:                      %s\n", report->zip.zip64_valid ? "VALIDATED" : "DETECTED / UNVERIFIED");
    }
    else if (report->type == AF_TYPE_PDF)
    {
        printf("\nPDF resource metadata\n---------------------\n");
        printf("Objects observed:            %llu\n", (unsigned long long)report->pdf.object_count);
        printf("Streams observed:            %llu\n", (unsigned long long)report->pdf.stream_count);
        printf("Filter declarations:         %llu\n", (unsigned long long)report->pdf.filter_count);
        printf("FlateDecode filters:         %llu\n", (unsigned long long)report->pdf.flate_filter_count);
        printf("Maximum filter chain:        %u\n", report->pdf.maximum_filter_chain);
        printf("Image objects:               %llu\n", (unsigned long long)report->pdf.image_count);
        printf("Embedded-file objects:       %llu\n", (unsigned long long)report->pdf.embedded_file_count);
        printf("Declared stream bytes:       %.2f MiB\n", to_mib(report->pdf.declared_stream_bytes));
        printf("Declared stream/file ratio:  %.2fx\n", report->pdf.declared_stream_ratio);
        printf("Total declared pixels:       %llu\n", (unsigned long long)report->pdf.total_declared_pixels);
        printf("Largest declared image:      %llu pixels\n", (unsigned long long)report->pdf.maximum_declared_pixels);
        printf("Estimated image memory:      %.2f MiB\n", to_mib(report->pdf.estimated_image_memory));
        printf("Structure depth heuristic:   %u\n", report->pdf.maximum_structure_depth);
        printf("XRef sections observed:      %u\n", report->pdf.xref_section_count);
        printf("startxref marker:            %s\n", report->pdf.startxref_present ? "YES" : "NO");
        printf("EOF marker:                  %s\n", report->pdf.eof_marker_present ? "YES" : "NO");
        printf("Recommended memory budget:   %.2f MiB\n", to_mib(report->pdf.recommended_memory_budget));
        printf("Analysis bounded/truncated:  %s\n", report->pdf.analysis_truncated ? "YES" : "NO");
    }

    printf("\nRisk score:  %u / 100\n", report->score);
    printf("Risk level:  %s\n", af_risk_name(report->level));
    printf("Notes:       %s\n", report->notes[0] ? report->notes : "None");
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
