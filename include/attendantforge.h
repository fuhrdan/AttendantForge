#ifndef ATTENDANTFORGE_H
#define ATTENDANTFORGE_H

#include <stddef.h>
#include <stdint.h>

#define AF_VERSION "0.1.0"

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
    const char *path;
    uint64_t file_size;
    AfFileType type;
    unsigned int score;
    AfRiskLevel level;
    char notes[512];
} AfReport;

int af_scan_file(const char *path, AfReport *report);
AfFileType af_detect_type(const unsigned char *header, size_t len);
const char *af_type_name(AfFileType type);
const char *af_risk_name(AfRiskLevel level);
AfRiskLevel af_score_to_level(unsigned int score);

#endif
