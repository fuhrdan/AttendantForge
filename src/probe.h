#ifndef AF_PROBE_H
#define AF_PROBE_H

#include <stdint.h>
#include <stddef.h>

typedef struct
{
    uint64_t memory_bytes;
    unsigned int cpu_seconds;
    unsigned int timeout_ms;
} AfProbeLimits;

typedef enum
{
    AF_PROBE_OK = 0,
    AF_PROBE_LIMIT_HIT = 1,
    AF_PROBE_TIMEOUT = 2,
    AF_PROBE_UNSUPPORTED = 3,
    AF_PROBE_ERROR = 4
} AfProbeStatus;

typedef struct
{
    AfProbeStatus status;
    int worker_scan_rc;
    int worker_exit_code;
    uint64_t peak_memory_bytes;
    uint64_t cpu_time_ms;
    uint64_t elapsed_time_ms;
    uint64_t temp_bytes_written;
    unsigned int measured_score;
    uint64_t predicted_memory_budget_bytes;
    char detail[256];
} AfProbeResult;

void af_probe_default_limits(AfProbeLimits *limits);
int af_run_probe(const char *exe_path, const char *file_path, const AfProbeLimits *limits, AfProbeResult *result);
int af_probe_worker_run(const char *file_path);
const char *af_probe_status_name(AfProbeStatus status);

#endif
