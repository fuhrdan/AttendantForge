#ifndef AF_BATCH_H
#define AF_BATCH_H
#include "attendantforge.h"
#include "policy.h"
#include <stdint.h>

typedef enum { AF_BATCH_TEXT=0, AF_BATCH_NDJSON, AF_BATCH_CSV } AfBatchFormat;
typedef struct {
    uint64_t files_seen, scanned, allowed, warned, blocked, errors, mismatches;
    uint64_t by_type[8];
    unsigned int highest_score;
} AfBatchSummary;
int af_batch_scan(const char *path, int recursive, AfBatchFormat format, const char *output_path, const AfPolicy *policy, AfBatchSummary *summary);
#endif
