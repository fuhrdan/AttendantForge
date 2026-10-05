#ifndef ATTENDANTFORGE_H
#define ATTENDANTFORGE_H

#include <stddef.h>
#include <stdint.h>

#define AF_VERSION "0.2.0"

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
    double aggregate_ratio;
    double maximum_entry_ratio;
    int central_directory_valid;
    int zip64_detected;
} AfZipMetrics;

typedef struct
{
    const char *path;
    uint64_t file_size;
    AfFileType type;
    unsigned int score;
    AfRiskLevel level;
    AfZipMetrics zip;
    char notes[768];
} AfReport;

int af_scan_file(const char *path, AfReport *report);
AfFileType af_detect_type(const unsigned char *header, size_t len);
const char *af_type_name(AfFileType type);
const char *af_risk_name(AfRiskLevel level);
AfRiskLevel af_score_to_level(unsigned int score);

#endif
