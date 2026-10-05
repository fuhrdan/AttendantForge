#ifndef AF_POLICY_H
#define AF_POLICY_H

#include <stddef.h>

typedef struct
{
    unsigned int warn_score;
    unsigned int block_score;
    int strict;
    double max_gzip_ratio;
    unsigned long long max_tar_entries;
    unsigned long long max_image_pixels;
    char profile[32];
    char policy_file[512];
} AfPolicy;

void af_policy_defaults(AfPolicy *policy);
int af_policy_apply_profile(AfPolicy *policy, const char *name, char *error, size_t error_size);
int af_policy_load_file(AfPolicy *policy, const char *path, char *error, size_t error_size);
int af_policy_validate(const AfPolicy *policy, char *error, size_t error_size);

#endif
