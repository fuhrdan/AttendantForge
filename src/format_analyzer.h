#ifndef AF_FORMAT_ANALYZER_H
#define AF_FORMAT_ANALYZER_H
#include "attendantforge.h"
#include <stdio.h>
#include <stddef.h>
int af_analyze_gzip(FILE *fp, uint64_t file_size, AfGzipMetrics *m, char *notes, size_t notes_size);
unsigned int af_score_gzip(const AfGzipMetrics *m, char *notes, size_t notes_size);
int af_analyze_tar(FILE *fp, uint64_t file_size, AfTarMetrics *m, char *notes, size_t notes_size);
unsigned int af_score_tar(const AfTarMetrics *m, char *notes, size_t notes_size);
int af_analyze_png(FILE *fp, uint64_t file_size, AfImageMetrics *m, char *notes, size_t notes_size);
int af_analyze_jpeg(FILE *fp, uint64_t file_size, AfImageMetrics *m, char *notes, size_t notes_size);
unsigned int af_score_image(const AfImageMetrics *m, uint64_t file_size, char *notes, size_t notes_size);
#endif
