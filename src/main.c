#include "attendantforge.h"
#include "policy.h"
#include "probe.h"
#include "batch.h"

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
    int json;
    int strict_set;
    int warn_set;
    int block_set;
    unsigned int warn_score;
    unsigned int block_score;
    const char *profile;
    const char *policy_file;
    const char *path;
    int memory_set;
    int cpu_set;
    int timeout_set;
    uint64_t memory_mib;
    unsigned int cpu_seconds;
    unsigned int timeout_ms;
    int recursive;
    AfBatchFormat batch_format;
    const char *output_path;
} AfCliOptions;

static void print_usage(const char *exe)
{
    printf("AttendantForge v%s\n", AF_VERSION);
    printf("Usage: %s scan [options] <file>\n", exe);
    printf("       %s probe [options] <file>\n", exe);
    printf("       %s batch [options] <directory>\n", exe);
    printf("       %s --version\n\n", exe);
    printf("Options:\n");
    printf("  --json                 Emit machine-readable JSON.\n");
    printf("  --profile NAME         desktop, upload-server, or high-security.\n");
    printf("  --policy FILE          Load key=value policy configuration.\n");
    printf("  --strict               Enforce a block threshold no higher than 60.\n");
    printf("  --warn-score N         Warning threshold, 0-100.\n");
    printf("  --block-score N        Blocking threshold, 0-100.\n");
    printf("  --memory-mib N         Probe memory ceiling in MiB (probe only; default 256).\n");
    printf("  --cpu-seconds N        Probe CPU ceiling in seconds (probe only; default 2).\n");
    printf("  --timeout-ms N         Probe elapsed-time ceiling in ms (probe only; default 3000).\n");
    printf("  --recursive            Recurse into subdirectories (batch only).\n");
    printf("  --ndjson FILE          Write one JSON object per scanned file (batch only; - for stdout).\n");
    printf("  --csv FILE             Write CSV telemetry (batch only; - for stdout).\n");
    printf("  --help                 Show this help.\n\n");
    printf("Precedence: defaults -> profile -> policy file -> explicit CLI overrides.\n");
    printf("Exit codes: 0 allow, 10 warn, 20 block/limit hit, 2 usage, 3 scan/probe error.\n");
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

static int parse_uint_range(const char *text, unsigned int min_value, unsigned int max_value, unsigned int *value)
{
    char *end = NULL;
    unsigned long parsed;
    errno = 0;
    parsed = strtoul(text, &end, 10);
    if (errno != 0 || end == text || *end != '\0' || parsed < min_value || parsed > max_value) return 0;
    *value = (unsigned int)parsed;
    return 1;
}

static int format_policy_block(const AfReport *report, const AfPolicy *policy)
{
    if (report == NULL || policy == NULL) return 0;
    if (!af_policy_format_allowed(policy, report->type)) return 1;
    if (report->type == AF_TYPE_GZIP && policy->max_gzip_ratio > 0.0 && report->gzip.expansion_ratio > policy->max_gzip_ratio) return 1;
    if (report->type == AF_TYPE_TAR && policy->max_tar_entries > 0ull && report->tar.entry_count > policy->max_tar_entries) return 1;
    if ((report->type == AF_TYPE_PNG || report->type == AF_TYPE_JPEG) && policy->max_image_pixels > 0ull && report->image.pixel_count > policy->max_image_pixels) return 1;
    return 0;
}

static const char *decision_name(const AfReport *report, const AfPolicy *policy)
{
    if (format_policy_block(report, policy)) return "BLOCK";
    if (report->score >= policy->block_score) return "BLOCK";
    if (report->score >= policy->warn_score) return "WARN";
    return "ALLOW";
}

static int decision_exit_code(const AfReport *report, const AfPolicy *policy)
{
    if (format_policy_block(report, policy)) return AF_EXIT_BLOCK;
    if (report->score >= policy->block_score) return AF_EXIT_BLOCK;
    if (report->score >= policy->warn_score) return AF_EXIT_WARN;
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

static void print_json_report(const AfReport *report, const AfPolicy *policy, const AfProbeResult *probe, const AfProbeLimits *limits)
{
    printf("{\n");
    printf("  \"tool\": \"AttendantForge\",\n  \"version\": \"%s\",\n", AF_VERSION);
    printf("  \"file\": "); json_string(report->path); printf(",\n");
    printf("  \"type\": \"%s\",\n", af_type_name(report->type));
    printf("  \"file_size_bytes\": %llu,\n", (unsigned long long)report->file_size);
    printf("  \"extension_signature_mismatch\": %s,\n", report->extension_signature_mismatch ? "true" : "false");
    printf("  \"risk\": {\"score\": %u, \"level\": \"%s\"},\n", report->score, af_risk_name(report->level));
    printf("  \"policy\": {\"profile\": "); json_string(policy->profile);
    printf(", \"policy_file\": "); json_string(policy->policy_file);
    printf(", \"warn_score\": %u, \"block_score\": %u, \"strict\": %s, \"max_gzip_ratio\": %.3f, \"max_tar_entries\": %llu, \"max_image_pixels\": %llu, \"decision\": \"%s\"},\n",
           policy->warn_score, policy->block_score, policy->strict ? "true" : "false", policy->max_gzip_ratio,
           policy->max_tar_entries, policy->max_image_pixels, decision_name(report, policy));

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
        printf("    \"xref_stream_count\": %llu,\n", (unsigned long long)report->pdf.xref_stream_count);
        printf("    \"object_stream_count\": %llu,\n", (unsigned long long)report->pdf.object_stream_count);
        printf("    \"xref_stream_reference_count\": %llu,\n", (unsigned long long)report->pdf.xref_stream_reference_count);
        printf("    \"incremental_update_count\": %llu,\n", (unsigned long long)report->pdf.incremental_update_count);
        printf("    \"indirect_reference_count\": %llu,\n", (unsigned long long)report->pdf.indirect_reference_count);
        printf("    \"unresolved_reference_count\": %llu,\n", (unsigned long long)report->pdf.unresolved_reference_count);
        printf("    \"startxref_offset\": %llu,\n", (unsigned long long)report->pdf.startxref_offset);
        printf("    \"startxref_offset_valid\": %s,\n", report->pdf.startxref_offset_valid ? "true" : "false");
        printf("    \"startxref_points_to_xref\": %s,\n", report->pdf.startxref_points_to_xref ? "true" : "false");
        printf("    \"startxref_points_to_xref_stream\": %s,\n", report->pdf.startxref_points_to_xref_stream ? "true" : "false");
        printf("    \"eof_marker_present\": %s,\n", report->pdf.eof_marker_present ? "true" : "false");
        printf("    \"analysis_truncated\": %s,\n", report->pdf.analysis_truncated ? "true" : "false");
        printf("    \"recommended_memory_budget_bytes\": %llu\n", (unsigned long long)report->pdf.recommended_memory_budget);
        printf("  },\n");
    }
    else if (report->type == AF_TYPE_GZIP)
    {
        printf("  \"gzip\": {\n");
        printf("    \"compressed_bytes\": %llu,\n", (unsigned long long)report->gzip.compressed_bytes);
        printf("    \"declared_uncompressed_bytes\": %llu,\n", (unsigned long long)report->gzip.declared_uncompressed_bytes);
        printf("    \"expansion_ratio\": %.6f,\n", report->gzip.expansion_ratio);
        printf("    \"isize_wrap_possible\": %s\n", report->gzip.isize_wrap_possible ? "true" : "false");
        printf("  },\n");
    }
    else if (report->type == AF_TYPE_TAR)
    {
        printf("  \"tar\": {\n");
        printf("    \"entry_count\": %llu,\n", (unsigned long long)report->tar.entry_count);
        printf("    \"declared_bytes\": %llu,\n", (unsigned long long)report->tar.total_declared_bytes);
        printf("    \"largest_entry_bytes\": %llu,\n", (unsigned long long)report->tar.largest_entry_bytes);
        printf("    \"path_traversal_count\": %llu,\n", (unsigned long long)report->tar.path_traversal_count);
        printf("    \"absolute_path_count\": %llu,\n", (unsigned long long)report->tar.absolute_path_count);
        printf("    \"declared_to_file_ratio\": %.6f\n", report->tar.declared_to_file_ratio);
        printf("  },\n");
    }
    else if (report->type == AF_TYPE_PNG || report->type == AF_TYPE_JPEG)
    {
        printf("  \"image\": {\n");
        printf("    \"width\": %llu, \"height\": %llu,\n", (unsigned long long)report->image.width, (unsigned long long)report->image.height);
        printf("    \"pixel_count\": %llu,\n", (unsigned long long)report->image.pixel_count);
        printf("    \"estimated_decoded_bytes\": %llu,\n", (unsigned long long)report->image.estimated_decoded_bytes);
        printf("    \"decoded_to_file_ratio\": %.6f\n", report->image.decoded_to_file_ratio);
        printf("  },\n");
    }

    if (probe != NULL && limits != NULL)
    {
        double memory_ratio = probe->predicted_memory_budget_bytes > 0 ? (double)probe->peak_memory_bytes / (double)probe->predicted_memory_budget_bytes : 0.0;
        printf("  \"probe\": {\n");
        printf("    \"status\": \"%s\",\n", af_probe_status_name(probe->status));
        printf("    \"peak_memory_bytes\": %llu,\n", (unsigned long long)probe->peak_memory_bytes);
        printf("    \"cpu_time_ms\": %llu,\n", (unsigned long long)probe->cpu_time_ms);
        printf("    \"elapsed_time_ms\": %llu,\n", (unsigned long long)probe->elapsed_time_ms);
        printf("    \"temp_bytes_written\": %llu,\n", (unsigned long long)probe->temp_bytes_written);
        printf("    \"predicted_memory_budget_bytes\": %llu,\n", (unsigned long long)probe->predicted_memory_budget_bytes);
        printf("    \"measured_to_predicted_memory_ratio\": %.6f,\n", memory_ratio);
        printf("    \"limits\": {\"memory_bytes\": %llu, \"cpu_seconds\": %u, \"timeout_ms\": %u},\n",
               (unsigned long long)limits->memory_bytes, limits->cpu_seconds, limits->timeout_ms);
        printf("    \"detail\": "); json_string(probe->detail); printf("\n  },\n");
    }
    printf("  \"notes\": "); json_string(report->notes[0] ? report->notes : "None"); printf("\n}\n");
}

static void print_text_report(const AfReport *report, const AfPolicy *policy, const AfProbeResult *probe, const AfProbeLimits *limits)
{
    printf("AttendantForge v%s\n\n", AF_VERSION);
    printf("File:        %s\n", report->path);
    printf("Type:        %s\n", af_type_name(report->type));
    printf("Size:        %.2f MiB\n", to_mib(report->file_size));
    printf("Extension/signature mismatch: %s\n", report->extension_signature_mismatch ? "YES" : "NO");

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
        printf("Classic xref sections:       %u\n", report->pdf.xref_section_count);
        printf("Xref streams:                %llu\n", (unsigned long long)report->pdf.xref_stream_count);
        printf("Object streams:              %llu\n", (unsigned long long)report->pdf.object_stream_count);
        printf("Incremental update links:    %llu\n", (unsigned long long)report->pdf.incremental_update_count);
        printf("Indirect references:         %llu\n", (unsigned long long)report->pdf.indirect_reference_count);
        printf("Unresolved references:       %llu\n", (unsigned long long)report->pdf.unresolved_reference_count);
        printf("startxref offset:             %llu\n", (unsigned long long)report->pdf.startxref_offset);
        printf("startxref recognized:         %s\n", (report->pdf.startxref_points_to_xref || report->pdf.startxref_points_to_xref_stream) ? "YES" : "NO");
        printf("Recommended memory budget:   %.2f MiB\n", to_mib(report->pdf.recommended_memory_budget));
    }

    else if (report->type == AF_TYPE_GZIP)
    {
        printf("\nGZIP resource metadata\n----------------------\n");
        printf("Declared expanded bytes:   %.2f MiB\n", to_mib(report->gzip.declared_uncompressed_bytes));
        printf("Expansion ratio:           %.2fx\n", report->gzip.expansion_ratio);
        printf("ISIZE wrap possible:       %s\n", report->gzip.isize_wrap_possible ? "YES" : "NO");
    }
    else if (report->type == AF_TYPE_TAR)
    {
        printf("\nTAR resource metadata\n---------------------\n");
        printf("Entries:                   %llu\n", (unsigned long long)report->tar.entry_count);
        printf("Declared content:          %.2f MiB\n", to_mib(report->tar.total_declared_bytes));
        printf("Largest entry:             %.2f MiB\n", to_mib(report->tar.largest_entry_bytes));
        printf("Traversal paths:           %llu\n", (unsigned long long)report->tar.path_traversal_count);
        printf("Absolute paths:            %llu\n", (unsigned long long)report->tar.absolute_path_count);
    }
    else if (report->type == AF_TYPE_PNG || report->type == AF_TYPE_JPEG)
    {
        printf("\nImage resource metadata\n-----------------------\n");
        printf("Dimensions:                %llu x %llu\n", (unsigned long long)report->image.width, (unsigned long long)report->image.height);
        printf("Pixel count:               %llu\n", (unsigned long long)report->image.pixel_count);
        printf("Estimated decoded memory:  %.2f MiB\n", to_mib(report->image.estimated_decoded_bytes));
        printf("Decoded/file ratio:        %.2fx\n", report->image.decoded_to_file_ratio);
    }

    if (probe != NULL && limits != NULL)
    {
        printf("\nIsolated parser probe\n---------------------\n");
        printf("Status:                     %s\n", af_probe_status_name(probe->status));
        printf("Peak memory:                %.2f MiB / %.2f MiB limit\n", to_mib(probe->peak_memory_bytes), to_mib(limits->memory_bytes));
        printf("CPU time:                   %llu ms / %u s limit\n", (unsigned long long)probe->cpu_time_ms, limits->cpu_seconds);
        printf("Elapsed time:               %llu ms / %u ms limit\n", (unsigned long long)probe->elapsed_time_ms, limits->timeout_ms);
        printf("Temporary bytes written:    %llu\n", (unsigned long long)probe->temp_bytes_written);
        printf("Predicted memory budget:    %.2f MiB\n", to_mib(probe->predicted_memory_budget_bytes));
        printf("Probe detail:               %s\n", probe->detail);
    }

    printf("\nRisk score:  %u / 100\n", report->score);
    printf("Risk level:  %s\n", af_risk_name(report->level));
    printf("Policy:      %s (profile %s, warn >= %u, block >= %u%s)\n", decision_name(report, policy),
           policy->profile, policy->warn_score, policy->block_score, policy->strict ? ", strict" : "");
    if (policy->policy_file[0] != '\0') printf("Policy file: %s\n", policy->policy_file);
    printf("Format caps:  gzip %.0fx, tar %llu entries, image %llu pixels\n", policy->max_gzip_ratio, policy->max_tar_entries, policy->max_image_pixels);
    printf("Notes:       %s\n", report->notes[0] ? report->notes : "None");
}

static int parse_cli(int argc, char **argv, AfCliOptions *opts)
{
    int i;
    memset(opts, 0, sizeof(*opts));
    for (i = 2; i < argc; i++)
    {
        if (strcmp(argv[i], "--json") == 0) opts->json = 1;
        else if (strcmp(argv[i], "--strict") == 0) opts->strict_set = 1;
        else if (strcmp(argv[i], "--profile") == 0)
        {
            if (++i >= argc) return 0;
            opts->profile = argv[i];
        }
        else if (strcmp(argv[i], "--policy") == 0)
        {
            if (++i >= argc) return 0;
            opts->policy_file = argv[i];
        }
        else if (strcmp(argv[i], "--warn-score") == 0)
        {
            if (++i >= argc || !parse_score(argv[i], &opts->warn_score)) return 0;
            opts->warn_set = 1;
        }
        else if (strcmp(argv[i], "--block-score") == 0)
        {
            if (++i >= argc || !parse_score(argv[i], &opts->block_score)) return 0;
            opts->block_set = 1;
        }
        else if (strcmp(argv[i], "--memory-mib") == 0)
        {
            unsigned int value;
            if (++i >= argc || !parse_uint_range(argv[i], 16u, 65536u, &value)) return 0;
            opts->memory_mib = value; opts->memory_set = 1;
        }
        else if (strcmp(argv[i], "--cpu-seconds") == 0)
        {
            if (++i >= argc || !parse_uint_range(argv[i], 1u, 3600u, &opts->cpu_seconds)) return 0;
            opts->cpu_set = 1;
        }
        else if (strcmp(argv[i], "--timeout-ms") == 0)
        {
            if (++i >= argc || !parse_uint_range(argv[i], 100u, 3600000u, &opts->timeout_ms)) return 0;
            opts->timeout_set = 1;
        }
        else if (strcmp(argv[i], "--recursive") == 0) opts->recursive = 1;
        else if (strcmp(argv[i], "--ndjson") == 0) { if (++i >= argc) return 0; opts->batch_format = AF_BATCH_NDJSON; opts->output_path = argv[i]; }
        else if (strcmp(argv[i], "--csv") == 0) { if (++i >= argc) return 0; opts->batch_format = AF_BATCH_CSV; opts->output_path = argv[i]; }
        else if (strcmp(argv[i], "--help") == 0) return 2;
        else if (argv[i][0] == '-') return 0;
        else if (opts->path == NULL) opts->path = argv[i];
        else return 0;
    }
    return opts->path != NULL ? 1 : 0;
}

int main(int argc, char **argv)
{
    AfReport report;
    AfPolicy policy;
    AfCliOptions opts;
    AfProbeLimits probe_limits;
    AfProbeResult probe_result;
    const AfProbeResult *probe_ptr = NULL;
    const AfProbeLimits *limits_ptr = NULL;
    char error[256] = {0};
    int parsed;
    int rc;
    int is_probe = 0;

    if (argc == 3 && strcmp(argv[1], "--probe-worker") == 0)
        return af_probe_worker_run(argv[2]);

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
    if (argc < 3 || (strcmp(argv[1], "scan") != 0 && strcmp(argv[1], "probe") != 0 && strcmp(argv[1], "batch") != 0))
    {
        print_usage(argv[0]);
        return AF_EXIT_USAGE;
    }
    is_probe = strcmp(argv[1], "probe") == 0;

    parsed = parse_cli(argc, argv, &opts);
    if (parsed == 2) { print_usage(argv[0]); return AF_EXIT_ALLOW; }
    if (parsed != 1) { fprintf(stderr, "Invalid %s options.\n", is_probe ? "probe" : "scan"); print_usage(argv[0]); return AF_EXIT_USAGE; }
    if (!is_probe && (opts.memory_set || opts.cpu_set || opts.timeout_set))
    {
        fprintf(stderr, "Probe resource-limit options require the 'probe' command.\n");
        return AF_EXIT_USAGE;
    }

    af_policy_defaults(&policy);
    if (opts.profile != NULL && af_policy_apply_profile(&policy, opts.profile, error, sizeof(error)) != 0)
    {
        fprintf(stderr, "Policy error: %s\n", error);
        return AF_EXIT_USAGE;
    }
    if (opts.policy_file != NULL && af_policy_load_file(&policy, opts.policy_file, error, sizeof(error)) != 0)
    {
        fprintf(stderr, "Policy error: %s\n", error);
        return AF_EXIT_USAGE;
    }
    if (opts.strict_set)
    {
        policy.strict = 1;
        if (!opts.block_set && policy.block_score > 60u) policy.block_score = 60u;
    }
    if (opts.warn_set) policy.warn_score = opts.warn_score;
    if (opts.block_set) policy.block_score = opts.block_score;
    if (policy.strict && !opts.block_set && policy.block_score > 60u) policy.block_score = 60u;
    if (af_policy_validate(&policy, error, sizeof(error)) != 0)
    {
        fprintf(stderr, "Policy error: %s\n", error);
        return AF_EXIT_USAGE;
    }

    if (strcmp(argv[1], "batch") == 0)
    {
        AfBatchSummary summary;
        if (opts.batch_format == AF_BATCH_TEXT && opts.output_path != NULL) { fprintf(stderr, "Batch output requires --ndjson or --csv.\n"); return AF_EXIT_USAGE; }
        rc = af_batch_scan(opts.path, opts.recursive, opts.batch_format, opts.output_path, &policy, &summary);
        if (rc != 0) { fprintf(stderr, "Unable to scan directory '%s' (error %d).\n", opts.path, rc); return AF_EXIT_SCAN_ERROR; }
        fprintf(stderr, "AttendantForge v%s batch summary: files=%llu scanned=%llu allow=%llu warn=%llu block=%llu errors=%llu mismatches=%llu highest_score=%u\n",
            AF_VERSION,(unsigned long long)summary.files_seen,(unsigned long long)summary.scanned,(unsigned long long)summary.allowed,(unsigned long long)summary.warned,(unsigned long long)summary.blocked,(unsigned long long)summary.errors,(unsigned long long)summary.mismatches,summary.highest_score);
        if (summary.blocked > 0) return AF_EXIT_BLOCK;
        if (summary.warned > 0) return AF_EXIT_WARN;
        return summary.errors > 0 ? AF_EXIT_SCAN_ERROR : AF_EXIT_ALLOW;
    }

    rc = af_scan_file(opts.path, &report);
    if (rc != 0)
    {
        fprintf(stderr, "Unable to scan '%s' (error %d).\n", opts.path, rc);
        return AF_EXIT_SCAN_ERROR;
    }

    if (is_probe)
    {
        af_probe_default_limits(&probe_limits);
        if (opts.memory_set) probe_limits.memory_bytes = opts.memory_mib * 1024ull * 1024ull;
        if (opts.cpu_set) probe_limits.cpu_seconds = opts.cpu_seconds;
        if (opts.timeout_set) probe_limits.timeout_ms = opts.timeout_ms;
        rc = af_run_probe(argv[0], opts.path, &probe_limits, &probe_result);
        if (rc != 0)
        {
            fprintf(stderr, "Unable to start isolated probe for '%s' (error %d).\n", opts.path, rc);
            return AF_EXIT_SCAN_ERROR;
        }
        if (probe_result.status == AF_PROBE_OK && probe_result.measured_score != report.score)
        {
            probe_result.status = AF_PROBE_LIMIT_HIT;
            snprintf(probe_result.detail, sizeof(probe_result.detail),
                     "The constrained worker produced a different risk score (%u vs parent %u), indicating degraded analysis under the configured resource ceiling.",
                     probe_result.measured_score, report.score);
        }
        probe_ptr = &probe_result;
        limits_ptr = &probe_limits;
    }

    if (opts.json) print_json_report(&report, &policy, probe_ptr, limits_ptr);
    else print_text_report(&report, &policy, probe_ptr, limits_ptr);

    if (is_probe)
    {
        if (probe_result.status == AF_PROBE_LIMIT_HIT || probe_result.status == AF_PROBE_TIMEOUT) return AF_EXIT_BLOCK;
        if (probe_result.status == AF_PROBE_ERROR || probe_result.status == AF_PROBE_UNSUPPORTED) return AF_EXIT_SCAN_ERROR;
    }
    return decision_exit_code(&report, &policy);
}
