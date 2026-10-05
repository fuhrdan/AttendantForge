#ifndef AF_PDF_ANALYZER_H
#define AF_PDF_ANALYZER_H

#include "attendantforge.h"
#include <stdio.h>

int af_analyze_pdf(FILE *fp, uint64_t file_size, AfPdfMetrics *metrics, char *notes, size_t notes_size);
unsigned int af_score_pdf(const AfPdfMetrics *metrics, uint64_t file_size, char *notes, size_t notes_size);

#endif
