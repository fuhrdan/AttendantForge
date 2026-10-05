#include "attendantforge.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define AF_EXIT_ALLOW 0
#define AF_EXIT_USAGE 2
#define AF_EXIT_SCAN_ERROR 3
#define AF_EXIT_WARN 10
#define AF_EXIT_BLOCK 20

typedef struct
{
    unsigned int warn_score;
    unsigned int block_score;
    int json;
    int strict;
} AfCliPolicy;

static void print_usage(const char *exe)
{
    printf("AttendantForge v%s\n", AF_VERSION);
    printf("Usage: %s scan [options] <file>\n", exe);
    printf("       %s --version\n\n", exe);
    printf("Options:\n");
    printf("  --json             Emit machine-readable JSON.\n");
    printf("  --strict           Default block threshold becomes 60 (HIGH).\n");
    printf("  --warn-score N     Warning threshold, 0-100 (default 60).\n");
    printf("  --block-score N    Blocking threshold, 0-100 (default 80, strict 60).\n");
    printf("  --help             Show this help.\n\n");
    printf("Exit codes: 0 allow, 10 warn, 20 block, 2 usage, 3 scan error.\n");
}

static double to_mib(uint64_t bytes)
{
    return (double)bytes / (1024.0 * 1024.0);
}

static int parse_score(const char *text, unsigned int *value)
{
    char *end = NULL;
    unsigned long parsed;
    errno = 0;
    parsed = strtoul(text, &end, 10);
    if (errno != 0 || end == text || *end != '\0' || parsed > 100ul) return 0;
    *value = (unsigned int)parsed;
    return 1;
}

static const char *decision_name(unsigned int score, const AfCliPolicy *policy)
{
    if (score >= policy->block_score) return "BLOCK";
    if (score >= policy->warn_score) return "WARN";
    return "ALLOW";
}

static int decision_exit_code(unsigned int score, const AfCliPolicy *policy)
{
    if (score >= policy->block_score) return AF_EXIT_BLOCK;
    if (score >= policy->warn_score) return AF_EXIT_WARN;
    return AF_EXIT_ALLOW;
}

static void json_string(const char *value)
{
    const unsigned char *p = (const unsigned char *)(value != NULL ? value : "");
    putchar('"');
    while (*p)
    {
        switch (*p)
        {
            case '"': fputs("\\\"", stdout); break;
            case '\\': fputs("\\\\", stdout); break;
            case '\b': fputs("\\b", stdout); break;
            case '\f': fputs("\\f", stdout); break;
            case '\n': fputs("\\n", stdout); break;
            case '\r': fputs("\\r", stdout); break;
            case '\t': fputs("\\t", stdout); break;
            default:
                if (*p < 0x20) printf("\\u%04x", (unsigned int)*p);
                else putchar((int)*p);
        }
        p++;
    }
    putchar('"');
}

static void print_json_report(const AfReport *report, const AfCliPolicy *policy)
{
    printf("{\n");
    printf("  \"tool\": \"AttendantForge\",\n  \"version\": \"%s\",\n", AF_VERSION);
    printf("  \"file\": "); json_string(report->path); printf(",\n");
    printf("  \"type\": \"%s\",\n", af_type_name(report->type));
    printf("  \"file_size_bytes\": %llu,\n", (unsigned long long)report->file_size);
    printf("  \"risk\": {\"score\": %u, \"level\": \"%s\"},\n", report->score, af_risk_name(report->level));
    printf("  \"policy\": {\"warn_score\": %u, \"block_score\": %u, \"strict\": %s, \"decision\": \"%s\"},\n",
           policy->warn_score, policy->block_score, policy->strict ? "true" : "false", decision_name(report->score, policy));

    if (report->type == AF_TYPE_ZIP)
    {
        printf("  \"zip\": {\n");
        printf("    \"entry_count\": %llu,\n", (unsigned long long)report->zip.entry_count);
        printf("    \"compressed_bytes\": %llu,\n", (unsigned long long)report->zip.total_compressed_size);
        printf("    \"declared_uncompressed_bytes\": %llu,\n", (unsigned long long)report->zip.total_uncompressed_size);
        printf("    \"aggregate_ratio\": %.6f,\n", report->zip.aggregate_ratio);
        printf("    \"maximum_entry_ratio\": %.6f,\n", report->zip.maximum_entry_ratio);
        printf("    \"nested_archive_candidates\": %llu,\n", (unsigned long long)report->zip.nested_archive_candidates);
        printf("    \"nested_archives_inspected\": %llu,\n", (unsigned long long)report->zip.nested_archives_inspected);
        printf("    \"path_traversal_count\": %llu,\n", (unsigned long long)report->zip.path_traversal_count);
        printf("    \"absolute_path_count\": %llu,\n", (unsigned long long)report->zip.absolute_path_count);
        printf("    \"recommended_disk_budget_bytes\": %llu,\n", (unsigned long long)report->zip.recommended_disk_budget);
        printf("    \"recommended_memory_budget_bytes\": %llu,\n", (unsigned long long)report->zip.recommended_memory_budget);
        printf("    \"zip64_detected\": %s,\n", report->zip.zip64_detected ? "true" : "false");
        printf("    \"central_directory_valid\": %s\n", report->zip.central_directory_valid ? "true" : "false");
        printf("  },\n");
    }
    else if (report->type == AF_TYPE_PDF)
    {
        printf("  \"pdf\": {\n");
        printf("    \"object_count\": %llu,\n", (unsigned long long)report->pdf.object_count);
        printf("    \"stream_count\": %llu,\n", (unsigned long long)report->pdf.stream_count);
        printf("    \"filter_count\": %llu,\n", (unsigned long long)report->pdf.filter_count);
        printf("    \"flate_filter_count\": %llu,\n", (unsigned long long)report->pdf.flate_filter_count);
        printf("    \"maximum_filter_chain\": %u,\n", report->pdf.maximum_filter_chain);
        printf("    \"image_count\": %llu,\n", (unsigned long long)report->pdf.image_count);
        printf("    \"embedded_file_count\": %llu,\n", (unsigned long long)report->pdf.embedded_file_count);
        printf("    \"declared_stream_bytes\": %llu,\n", (unsigned long long)report->pdf.declared_stream_bytes);
        printf("    \"declared_stream_ratio\": %.6f,\n", report->pdf.declared_stream_ratio);
        printf("    \"total_declared_pixels\": %llu,\n", (unsigned long long)report->pdf.total_declared_pixels);
        printf("    \"estimated_image_memory_bytes\": %llu,\n", (unsigned long long)report->pdf.estimated_image_memory);
        printf("    \"maximum_structure_depth\": %u,\n", report->pdf.maximum_structure_depth);
        printf("    \"xref_section_count\": %u,\n", report->pdf.xref_section_count);
        printf("    \"indirect_reference_count\": %llu,\n", (unsigned long long)report->pdf.indirect_reference_count);
        printf("    \"unresolved_reference_count\": %llu,\n", (unsigned long long)report->pdf.unresolved_reference_count);
        printf("    \"startxref_offset\": %llu,\n", (unsigned long long)report->pdf.startxref_offset);
        printf("    \"startxref_offset_valid\": %s,\n", report->pdf.startxref_offset_valid ? "true" : "false");
        printf("    \"startxref_points_to_xref\": %s,\n", report->pdf.startxref_points_to_xref ? "true" : "false");
        printf("    \"eof_marker_present\": %s,\n", report->pdf.eof_marker_present ? "true" : "false");
        printf("    \"analysis_truncated\": %s,\n", report->pdf.analysis_truncated ? "true" : "false");
        printf("    \"recommended_memory_budget_bytes\": %llu\n", (unsigned long long)report->pdf.recommended_memory_budget);
        printf("  },\n");
    }
    printf("  \"notes\": "); json_string(report->notes[0] ? report->notes : "None"); printf("\n}\n");
}

static void print_text_report(const AfReport *report, const AfCliPolicy *policy)
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
        printf("Nested archive candidates:  %llu\n", (unsigned long long)report->zip.nested_archive_candidates);
        printf("Traversal paths:            %llu\n", (unsigned long long)report->zip.path_traversal_count);
        printf("Absolute paths:             %llu\n", (unsigned long long)report->zip.absolute_path_count);
        printf("Recommended disk budget:    %.2f MiB\n", to_mib(report->zip.recommended_disk_budget));
        printf("Recommended memory budget:  %.2f MiB\n", to_mib(report->zip.recommended_memory_budget));
    }
    else if (report->type == AF_TYPE_PDF)
    {
        printf("\nPDF resource metadata\n---------------------\n");
        printf("Objects observed:            %llu\n", (unsigned long long)report->pdf.object_count);
        printf("Streams observed:            %llu\n", (unsigned long long)report->pdf.stream_count);
        printf("Filter declarations:         %llu\n", (unsigned long long)report->pdf.filter_count);
        printf("Maximum filter chain:        %u\n", report->pdf.maximum_filter_chain);
        printf("Image objects:               %llu\n", (unsigned long long)report->pdf.image_count);
        printf("Declared stream/file ratio:  %.2fx\n", report->pdf.declared_stream_ratio);
        printf("Estimated image memory:      %.2f MiB\n", to_mib(report->pdf.estimated_image_memory));
        printf("Indirect references:         %llu\n", (unsigned long long)report->pdf.indirect_reference_count);
        printf("Unresolved references:       %llu\n", (unsigned long long)report->pdf.unresolved_reference_count);
        printf("startxref offset:             %llu\n", (unsigned long long)report->pdf.startxref_offset);
        printf("startxref valid:              %s\n", report->pdf.startxref_offset_valid ? "YES" : "NO");
        printf("startxref -> xref:            %s\n", report->pdf.startxref_points_to_xref ? "YES" : "NO");
        printf("Recommended memory budget:   %.2f MiB\n", to_mib(report->pdf.recommended_memory_budget));
    }

    printf("\nRisk score:  %u / 100\n", report->score);
    printf("Risk level:  %s\n", af_risk_name(report->level));
    printf("Policy:      %s (warn >= %u, block >= %u%s)\n", decision_name(report->score, policy),
           policy->warn_score, policy->block_score, policy->strict ? ", strict" : "");
    printf("Notes:       %s\n", report->notes[0] ? report->notes : "None");
}

int main(int argc, char **argv)
{
    AfReport report;
    AfCliPolicy policy = {60u, 80u, 0, 0};
    const char *path = NULL;
    int explicit_block = 0;
    int rc;
    int i;

    if (argc == 2 && strcmp(argv[1], "--version") == 0)
    {
        printf("%s\n", AF_VERSION);
        return AF_EXIT_ALLOW;
    }
    if (argc == 2 && strcmp(argv[1], "--help") == 0)
    {
        print_usage(argv[0]);
        return AF_EXIT_ALLOW;
    }
    if (argc < 3 || strcmp(argv[1], "scan") != 0)
    {
        print_usage(argv[0]);
        return AF_EXIT_USAGE;
    }

    for (i = 2; i < argc; i++)
    {
        if (strcmp(argv[i], "--json") == 0) policy.json = 1;
        else if (strcmp(argv[i], "--strict") == 0) policy.strict = 1;
        else if (strcmp(argv[i], "--warn-score") == 0)
        {
            if (++i >= argc || !parse_score(argv[i], &policy.warn_score)) { fprintf(stderr, "Invalid --warn-score.\n"); return AF_EXIT_USAGE; }
        }
        else if (strcmp(argv[i], "--block-score") == 0)
        {
            if (++i >= argc || !parse_score(argv[i], &policy.block_score)) { fprintf(stderr, "Invalid --block-score.\n"); return AF_EXIT_USAGE; }
            explicit_block = 1;
        }
        else if (argv[i][0] == '-')
        {
            fprintf(stderr, "Unknown option: %s\n", argv[i]);
            return AF_EXIT_USAGE;
        }
        else if (path == NULL) path = argv[i];
        else { fprintf(stderr, "Only one input file may be scanned at a time.\n"); return AF_EXIT_USAGE; }
    }

    if (path == NULL) { print_usage(argv[0]); return AF_EXIT_USAGE; }
    if (policy.strict && !explicit_block) policy.block_score = 60u;
    if (policy.warn_score > policy.block_score)
    {
        fprintf(stderr, "warn-score must be <= block-score.\n");
        return AF_EXIT_USAGE;
    }

    rc = af_scan_file(path, &report);
    if (rc != 0)
    {
        fprintf(stderr, "Unable to scan '%s' (error %d).\n", path, rc);
        return AF_EXIT_SCAN_ERROR;
    }

    if (policy.json) print_json_report(&report, &policy);
    else print_text_report(&report, &policy);
    return decision_exit_code(report.score, &policy);
}
