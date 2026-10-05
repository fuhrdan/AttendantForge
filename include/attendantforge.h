#ifndef ATTENDANTFORGE_H
#define ATTENDANTFORGE_H

#include <stddef.h>
#include <stdint.h>

#define AF_VERSION "0.3.0"
#define AF_MAX_NESTED_DEPTH 3u
#define AF_MAX_NESTED_ARCHIVES 64u

typedef enum
{
    AF_TYPE_UNKNOWN = 0,
    AF_TYPE_ZIP,
    AF_TYPE_PDF
} AfFileType;

typedef enum
{
    AF_RISK_LOW = 0,
    AF_RISK_MEDIUM,
    AF_RISK_HIGH,
    AF_RISK_CRITICAL
} AfRiskLevel;

typedef struct
{
    uint64_t entry_count;
    uint64_t total_compressed_size;
    uint64_t total_uncompressed_size;
    uint64_t largest_compressed_size;
    uint64_t largest_uncompressed_size;
    uint64_t path_traversal_count;
    uint64_t absolute_path_count;
    uint64_t nested_archive_candidates;
    uint64_t nested_archives_inspected;
    uint64_t nested_entries_total;
    uint64_t recommended_disk_budget;
    uint64_t recommended_memory_budget;
    double aggregate_ratio;
    double maximum_entry_ratio;
    unsigned int maximum_nested_depth;
    int central_directory_valid;
    int zip64_detected;
    int zip64_valid;
    int recursion_limit_hit;
} AfZipMetrics;

typedef struct
{
    const char *path;
    uint64_t file_size;
    AfFileType type;
    unsigned int score;
    AfRiskLevel level;
    AfZipMetrics zip;
    char notes[1536];
} AfReport;

int af_scan_file(const char *path, AfReport *report);
AfFileType af_detect_type(const unsigned char *header, size_t len);
const char *af_type_name(AfFileType type);
const char *af_risk_name(AfRiskLevel level);
AfRiskLevel af_score_to_level(unsigned int score);

#endif
