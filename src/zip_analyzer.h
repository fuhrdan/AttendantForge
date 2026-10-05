#ifndef AF_ZIP_ANALYZER_H
#define AF_ZIP_ANALYZER_H

#include "attendantforge.h"
#include <stdio.h>

int af_analyze_zip(FILE *fp, uint64_t file_size, AfZipMetrics *metrics, char *notes, size_t notes_size);
unsigned int af_score_zip(const AfZipMetrics *metrics, char *notes, size_t notes_size);

#endif
