#ifndef _WIN32
#define _GNU_SOURCE
#endif

#include "probe.h"
#include "attendantforge.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <fcntl.h>
#include <io.h>
#else
#include <errno.h>
#include <signal.h>
#include <sys/resource.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#endif

#define AF_PROBE_MAGIC 0x41465037u

typedef struct
{
    uint32_t magic;
    int32_t scan_rc;
    uint32_t score;
    uint64_t predicted_memory_budget_bytes;
} AfProbeWire;

static uint64_t now_ms(void)
{
#ifdef _WIN32
    return (uint64_t)GetTickCount64();
#else
    struct timespec ts;
    if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0) return 0;
    return (uint64_t)ts.tv_sec * 1000ull + (uint64_t)ts.tv_nsec / 1000000ull;
#endif
}

void af_probe_default_limits(AfProbeLimits *limits)
{
    if (limits == NULL) return;
    limits->memory_bytes = 256ull * 1024ull * 1024ull;
    limits->cpu_seconds = 2u;
    limits->timeout_ms = 3000u;
}

const char *af_probe_status_name(AfProbeStatus status)
{
    switch (status)
    {
        case AF_PROBE_OK: return "OK";
        case AF_PROBE_LIMIT_HIT: return "LIMIT_HIT";
        case AF_PROBE_TIMEOUT: return "TIMEOUT";
        case AF_PROBE_UNSUPPORTED: return "UNSUPPORTED";
        default: return "ERROR";
    }
}

int af_probe_worker_run(const char *file_path)
{
    AfReport report;
    AfProbeWire wire;
    int rc;
    memset(&wire, 0, sizeof(wire));
    wire.magic = AF_PROBE_MAGIC;
    rc = af_scan_file(file_path, &report);
    wire.scan_rc = rc;
    if (rc == 0)
    {
        wire.score = report.score;
        if (report.type == AF_TYPE_ZIP) wire.predicted_memory_budget_bytes = report.zip.recommended_memory_budget;
        else if (report.type == AF_TYPE_PDF) wire.predicted_memory_budget_bytes = report.pdf.recommended_memory_budget;
    }
#ifdef _WIN32
    _setmode(_fileno(stdout), _O_BINARY);
#endif
    if (fwrite(&wire, 1, sizeof(wire), stdout) != sizeof(wire)) return 111;
    fflush(stdout);
    return rc == 0 ? 0 : 112;
}

#ifndef _WIN32
static int read_wire_fd(int fd, AfProbeWire *wire)
{
    unsigned char *p = (unsigned char *)wire;
    size_t total = 0;
    while (total < sizeof(*wire))
    {
        ssize_t got = read(fd, p + total, sizeof(*wire) - total);
        if (got == 0) break;
        if (got < 0)
        {
            if (errno == EINTR) continue;
            return -1;
        }
        total += (size_t)got;
    }
    return total == sizeof(*wire) ? 0 : -1;
}

int af_run_probe(const char *exe_path, const char *file_path, const AfProbeLimits *limits, AfProbeResult *result)
{
    int pipefd[2];
    pid_t pid;
    uint64_t start;
    int status = 0;
    struct rusage usage;
    AfProbeWire wire;
    int timed_out = 0;

    if (exe_path == NULL || file_path == NULL || limits == NULL || result == NULL) return -1;
    memset(result, 0, sizeof(*result));
    memset(&wire, 0, sizeof(wire));
    if (pipe(pipefd) != 0) return -2;

    start = now_ms();
    pid = fork();
    if (pid < 0)
    {
        close(pipefd[0]); close(pipefd[1]);
        return -3;
    }
    if (pid == 0)
    {
        struct rlimit rl;
        close(pipefd[0]);
        if (dup2(pipefd[1], STDOUT_FILENO) < 0) _exit(120);
        close(pipefd[1]);

        rl.rlim_cur = rl.rlim_max = (rlim_t)limits->memory_bytes;
        if (setrlimit(RLIMIT_AS, &rl) != 0) _exit(121);
        rl.rlim_cur = rl.rlim_max = (rlim_t)limits->cpu_seconds;
        if (setrlimit(RLIMIT_CPU, &rl) != 0) _exit(122);

        execlp(exe_path, exe_path, "--probe-worker", file_path, (char *)NULL);
        _exit(123);
    }

    close(pipefd[1]);
    memset(&usage, 0, sizeof(usage));
    for (;;)
    {
        pid_t w = wait4(pid, &status, WNOHANG, &usage);
        if (w == pid) break;
        if (w < 0)
        {
            close(pipefd[0]);
            return -4;
        }
        if (now_ms() - start >= limits->timeout_ms)
        {
            timed_out = 1;
            kill(pid, SIGKILL);
            wait4(pid, &status, 0, &usage);
            break;
        }
        { struct timespec req = {0, 10000000L}; nanosleep(&req, NULL); }
    }

    result->elapsed_time_ms = now_ms() - start;
#if defined(__APPLE__)
    result->peak_memory_bytes = (uint64_t)usage.ru_maxrss;
#else
    result->peak_memory_bytes = (uint64_t)usage.ru_maxrss * 1024ull;
#endif
    result->cpu_time_ms = (uint64_t)usage.ru_utime.tv_sec * 1000ull + (uint64_t)usage.ru_utime.tv_usec / 1000ull +
                          (uint64_t)usage.ru_stime.tv_sec * 1000ull + (uint64_t)usage.ru_stime.tv_usec / 1000ull;
    result->temp_bytes_written = 0;

    if (!timed_out && read_wire_fd(pipefd[0], &wire) == 0 && wire.magic == AF_PROBE_MAGIC)
    {
        result->worker_scan_rc = wire.scan_rc;
        result->measured_score = wire.score;
        result->predicted_memory_budget_bytes = wire.predicted_memory_budget_bytes;
    }
    close(pipefd[0]);

    if (timed_out)
    {
        result->status = AF_PROBE_TIMEOUT;
        snprintf(result->detail, sizeof(result->detail), "Elapsed-time ceiling reached.");
        return 0;
    }
    if (WIFSIGNALED(status))
    {
        int sig = WTERMSIG(status);
        result->worker_exit_code = 128 + sig;
        result->status = AF_PROBE_LIMIT_HIT;
        snprintf(result->detail, sizeof(result->detail), "Probe worker terminated by signal %d; a CPU or memory ceiling may have been reached.", sig);
        return 0;
    }
    result->worker_exit_code = WIFEXITED(status) ? WEXITSTATUS(status) : -1;
    if (wire.magic == AF_PROBE_MAGIC && wire.scan_rc != 0)
    {
        result->status = AF_PROBE_LIMIT_HIT;
        snprintf(result->detail, sizeof(result->detail), "The parser completed in the parent scan but could not complete inside the constrained worker; the configured resource ceiling was insufficient.");
        return 0;
    }
    if (result->worker_exit_code != 0 || wire.magic != AF_PROBE_MAGIC)
    {
        result->status = AF_PROBE_ERROR;
        snprintf(result->detail, sizeof(result->detail), "Probe worker failed (exit %d).", result->worker_exit_code);
        return 0;
    }
    result->status = AF_PROBE_OK;
    snprintf(result->detail, sizeof(result->detail), "Isolated parser probe completed within all enforced limits.");
    return 0;
}

#else

static void quote_windows_arg(char *dst, size_t dst_size, const char *src)
{
    size_t used = 0;
    if (dst_size == 0) return;
    dst[0] = '\0';
    if (used + 1 < dst_size) dst[used++] = '"';
    while (*src && used + 2 < dst_size)
    {
        if (*src == '"' || *src == '\\') dst[used++] = '\\';
        dst[used++] = *src++;
    }
    if (used + 1 < dst_size) dst[used++] = '"';
    dst[used] = '\0';
}

int af_run_probe(const char *exe_path, const char *file_path, const AfProbeLimits *limits, AfProbeResult *result)
{
    SECURITY_ATTRIBUTES sa;
    HANDLE read_pipe = NULL, write_pipe = NULL;
    STARTUPINFOA si;
    PROCESS_INFORMATION pi;
    HANDLE job = NULL;
    JOBOBJECT_EXTENDED_LIMIT_INFORMATION ji;
    JOBOBJECT_BASIC_LIMIT_INFORMATION bi;
    FILETIME create_t, exit_t, kernel_t, user_t;
    LARGE_INTEGER kernel, user;
    char qexe[2048], qfile[4096], cmd[8192];
    AfProbeWire wire;
    DWORD got = 0;
    DWORD wait_rc;
    uint64_t start;

    if (exe_path == NULL || file_path == NULL || limits == NULL || result == NULL) return -1;
    memset(result, 0, sizeof(*result));
    memset(&wire, 0, sizeof(wire));
    memset(&sa, 0, sizeof(sa)); sa.nLength = sizeof(sa); sa.bInheritHandle = TRUE;
    if (!CreatePipe(&read_pipe, &write_pipe, &sa, 0)) return -2;
    SetHandleInformation(read_pipe, HANDLE_FLAG_INHERIT, 0);

    memset(&si, 0, sizeof(si)); si.cb = sizeof(si);
    si.dwFlags = STARTF_USESTDHANDLES;
    si.hStdOutput = write_pipe;
    si.hStdError = GetStdHandle(STD_ERROR_HANDLE);
    si.hStdInput = GetStdHandle(STD_INPUT_HANDLE);
    memset(&pi, 0, sizeof(pi));

    quote_windows_arg(qexe, sizeof(qexe), exe_path);
    quote_windows_arg(qfile, sizeof(qfile), file_path);
    snprintf(cmd, sizeof(cmd), "%s --probe-worker %s", qexe, qfile);

    if (!CreateProcessA(NULL, cmd, NULL, NULL, TRUE, CREATE_SUSPENDED | CREATE_NO_WINDOW, NULL, NULL, &si, &pi))
    {
        CloseHandle(read_pipe); CloseHandle(write_pipe); return -3;
    }
    CloseHandle(write_pipe); write_pipe = NULL;

    job = CreateJobObjectA(NULL, NULL);
    if (job == NULL)
    {
        TerminateProcess(pi.hProcess, 124); CloseHandle(pi.hThread); CloseHandle(pi.hProcess); CloseHandle(read_pipe); return -4;
    }
    memset(&ji, 0, sizeof(ji));
    ji.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_PROCESS_MEMORY | JOB_OBJECT_LIMIT_PROCESS_TIME | JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
    ji.ProcessMemoryLimit = (SIZE_T)limits->memory_bytes;
    ji.BasicLimitInformation.PerProcessUserTimeLimit.QuadPart = (LONGLONG)limits->cpu_seconds * 10000000ll;
    if (!SetInformationJobObject(job, JobObjectExtendedLimitInformation, &ji, sizeof(ji)) || !AssignProcessToJobObject(job, pi.hProcess))
    {
        TerminateProcess(pi.hProcess, 125); CloseHandle(job); CloseHandle(pi.hThread); CloseHandle(pi.hProcess); CloseHandle(read_pipe); return -5;
    }

    start = now_ms();
    ResumeThread(pi.hThread);
    wait_rc = WaitForSingleObject(pi.hProcess, limits->timeout_ms);
    if (wait_rc == WAIT_TIMEOUT)
    {
        TerminateJobObject(job, 126);
        WaitForSingleObject(pi.hProcess, INFINITE);
        result->status = AF_PROBE_TIMEOUT;
        snprintf(result->detail, sizeof(result->detail), "Elapsed-time ceiling reached.");
    }

    result->elapsed_time_ms = now_ms() - start;
    if (GetProcessTimes(pi.hProcess, &create_t, &exit_t, &kernel_t, &user_t))
    {
        kernel.LowPart = kernel_t.dwLowDateTime; kernel.HighPart = (LONG)kernel_t.dwHighDateTime;
        user.LowPart = user_t.dwLowDateTime; user.HighPart = (LONG)user_t.dwHighDateTime;
        result->cpu_time_ms = (uint64_t)((kernel.QuadPart + user.QuadPart) / 10000ll);
    }
    memset(&ji, 0, sizeof(ji));
    if (QueryInformationJobObject(job, JobObjectExtendedLimitInformation, &ji, sizeof(ji), NULL))
        result->peak_memory_bytes = (uint64_t)ji.PeakProcessMemoryUsed;
    result->temp_bytes_written = 0;

    ReadFile(read_pipe, &wire, sizeof(wire), &got, NULL);
    if (got == sizeof(wire) && wire.magic == AF_PROBE_MAGIC)
    {
        result->worker_scan_rc = wire.scan_rc;
        result->measured_score = wire.score;
        result->predicted_memory_budget_bytes = wire.predicted_memory_budget_bytes;
    }
    GetExitCodeProcess(pi.hProcess, (LPDWORD)&result->worker_exit_code);

    if (wait_rc != WAIT_TIMEOUT)
    {
        memset(&bi, 0, sizeof(bi));
        if (QueryInformationJobObject(job, JobObjectBasicLimitInformation, &bi, sizeof(bi), NULL) &&
            result->worker_exit_code != 0 && got != sizeof(wire))
        {
            result->status = AF_PROBE_LIMIT_HIT;
            snprintf(result->detail, sizeof(result->detail), "Probe worker stopped before returning a report; an enforced CPU or memory ceiling may have been reached.");
        }
        else if (got == sizeof(wire) && wire.magic == AF_PROBE_MAGIC && wire.scan_rc != 0)
        {
            result->status = AF_PROBE_LIMIT_HIT;
            snprintf(result->detail, sizeof(result->detail), "The parser completed in the parent scan but could not complete inside the constrained worker; the configured resource ceiling was insufficient.");
        }
        else if (result->worker_exit_code != 0 || got != sizeof(wire) || wire.magic != AF_PROBE_MAGIC)
        {
            result->status = AF_PROBE_ERROR;
            snprintf(result->detail, sizeof(result->detail), "Probe worker failed (exit %d).", result->worker_exit_code);
        }
        else
        {
            result->status = AF_PROBE_OK;
            snprintf(result->detail, sizeof(result->detail), "Isolated parser probe completed within all enforced limits.");
        }
    }

    CloseHandle(read_pipe); CloseHandle(job); CloseHandle(pi.hThread); CloseHandle(pi.hProcess);
    return 0;
}
#endif
