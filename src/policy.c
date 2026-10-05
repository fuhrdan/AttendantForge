#include "policy.h"
#include "attendantforge.h"

#include <ctype.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void set_error(char *error, size_t error_size, const char *text)
{
    if (error == NULL || error_size == 0) return;
    snprintf(error, error_size, "%s", text != NULL ? text : "policy error");
}

static char *trim(char *s)
{
    char *end;
    while (*s && isspace((unsigned char)*s)) s++;
    if (*s == '\0') return s;
    end = s + strlen(s) - 1;
    while (end > s && isspace((unsigned char)*end)) *end-- = '\0';
    return s;
}

static int parse_score(const char *text, unsigned int *value)
{
    char *end = NULL;
    unsigned long parsed;
    errno = 0;
    parsed = strtoul(text, &end, 10);
    if (errno != 0 || end == text || *end != '\0' || parsed > 100ul) return 0;
    *value = (unsigned int)parsed;
    return 1;
}

static int parse_bool(const char *text, int *value)
{
    if (strcmp(text, "true") == 0 || strcmp(text, "1") == 0 || strcmp(text, "yes") == 0)
    {
        *value = 1;
        return 1;
    }
    if (strcmp(text, "false") == 0 || strcmp(text, "0") == 0 || strcmp(text, "no") == 0)
    {
        *value = 0;
        return 1;
    }
    return 0;
}

void af_policy_defaults(AfPolicy *policy)
{
    if (policy == NULL) return;
    memset(policy, 0, sizeof(*policy));
    policy->warn_score = 60u;
    policy->block_score = 80u;
    policy->max_gzip_ratio = 500.0;
    policy->max_tar_entries = 100000ull;
    policy->max_image_pixels = 250000000ull;
    policy->allow_formats = 0xffffffffu;
    policy->deny_formats = 0u;
    snprintf(policy->profile, sizeof(policy->profile), "%s", "desktop");
}

int af_policy_apply_profile(AfPolicy *policy, const char *name, char *error, size_t error_size)
{
    if (policy == NULL || name == NULL) return -1;
    if (strcmp(name, "desktop") == 0)
    {
        policy->warn_score = 60u;
        policy->block_score = 80u;
    policy->max_gzip_ratio = 500.0;
    policy->max_tar_entries = 100000ull;
    policy->max_image_pixels = 250000000ull;
        policy->strict = 0;
        policy->max_gzip_ratio = 500.0; policy->max_tar_entries = 100000ull; policy->max_image_pixels = 250000000ull;
    }
    else if (strcmp(name, "upload-server") == 0)
    {
        policy->warn_score = 45u;
        policy->block_score = 70u;
        policy->strict = 0;
        policy->max_gzip_ratio = 250.0; policy->max_tar_entries = 50000ull; policy->max_image_pixels = 150000000ull;
    }
    else if (strcmp(name, "high-security") == 0)
    {
        policy->warn_score = 30u;
        policy->block_score = 60u;
        policy->strict = 1;
        policy->max_gzip_ratio = 100.0; policy->max_tar_entries = 10000ull; policy->max_image_pixels = 80000000ull;
    }
    else
    {
        set_error(error, error_size, "unknown profile (expected desktop, upload-server, or high-security)");
        return -1;
    }
    snprintf(policy->profile, sizeof(policy->profile), "%s", name);
    return 0;
}

int af_policy_validate(const AfPolicy *policy, char *error, size_t error_size)
{
    if (policy == NULL) return -1;
    if (policy->warn_score > 100u || policy->block_score > 100u)
    {
        set_error(error, error_size, "policy scores must be between 0 and 100");
        return -1;
    }
    if (policy->warn_score > policy->block_score)
    {
        set_error(error, error_size, "warn_score must be <= block_score");
        return -1;
    }
    return 0;
}

static int parse_u64(const char *text, unsigned long long *value)
{
    char *end = NULL; unsigned long long parsed; errno = 0; parsed = strtoull(text, &end, 10);
    if (errno != 0 || end == text || *end != '\0') return 0;
    *value = parsed;
    return 1;
}
static int parse_double_positive(const char *text, double *value)
{
    char *end = NULL; double parsed; errno = 0; parsed = strtod(text, &end);
    if (errno != 0 || end == text || *end != '\0' || parsed < 0.0) return 0;
    *value = parsed;
    return 1;
}


static uint32_t format_name_bit(const char *name)
{
    if (strcmp(name, "ZIP") == 0) return AF_FORMAT_BIT(AF_TYPE_ZIP);
    if (strcmp(name, "PDF") == 0) return AF_FORMAT_BIT(AF_TYPE_PDF);
    if (strcmp(name, "GZIP") == 0) return AF_FORMAT_BIT(AF_TYPE_GZIP);
    if (strcmp(name, "TAR") == 0) return AF_FORMAT_BIT(AF_TYPE_TAR);
    if (strcmp(name, "PNG") == 0) return AF_FORMAT_BIT(AF_TYPE_PNG);
    if (strcmp(name, "JPEG") == 0 || strcmp(name, "JPG") == 0) return AF_FORMAT_BIT(AF_TYPE_JPEG);
    if (strcmp(name, "UNKNOWN") == 0) return AF_FORMAT_BIT(AF_TYPE_UNKNOWN);
    return 0u;
}

static int parse_format_list(const char *text, uint32_t *mask, int allow_star)
{
    char copy[512]; char *tok; uint32_t result = 0u;
    if (text == NULL || mask == NULL) return 0;
    if (allow_star && strcmp(text, "*") == 0) { *mask = 0xffffffffu; return 1; }
    snprintf(copy, sizeof(copy), "%s", text);
    tok = strtok(copy, ",");
    while (tok != NULL)
    {
        char upper[32]; size_t i, n; uint32_t bit;
        tok = trim(tok); n = strlen(tok); if (n >= sizeof(upper)) return 0;
        for (i = 0; i < n; i++)
            upper[i] = (char)toupper((unsigned char)tok[i]);
        upper[n] = '\0';
        bit = format_name_bit(upper); if (bit == 0u && strcmp(upper,"UNKNOWN") != 0) return 0;
        result |= bit; tok = strtok(NULL, ",");
    }
    *mask = result; return 1;
}

int af_policy_format_allowed(const AfPolicy *policy, int file_type)
{
    uint32_t bit;
    if (policy == NULL || file_type < 0 || file_type > 31) return 0;
    bit = AF_FORMAT_BIT(file_type);
    return ((policy->allow_formats & bit) != 0u) && ((policy->deny_formats & bit) == 0u);
}

int af_policy_load_file(AfPolicy *policy, const char *path, char *error, size_t error_size)
{
    FILE *fp;
    char line[1024];
    unsigned int line_number = 0;
    if (policy == NULL || path == NULL) return -1;
    fp = fopen(path, "r");
    if (fp == NULL)
    {
        set_error(error, error_size, "unable to open policy file");
        return -1;
    }
    while (fgets(line, sizeof(line), fp) != NULL)
    {
        char *p;
        char *eq;
        char *key;
        char *value;
        line_number++;
        p = trim(line);
        if (*p == '\0' || *p == '#' || *p == ';') continue;
        eq = strchr(p, '=');
        if (eq == NULL)
        {
            snprintf(error, error_size, "policy line %u is missing '='", line_number);
            fclose(fp);
            return -1;
        }
        *eq = '\0';
        key = trim(p);
        value = trim(eq + 1);
        if (strcmp(key, "profile") == 0)
        {
            if (af_policy_apply_profile(policy, value, error, error_size) != 0) { fclose(fp); return -1; }
        }
        else if (strcmp(key, "warn_score") == 0)
        {
            if (!parse_score(value, &policy->warn_score)) { set_error(error, error_size, "invalid warn_score"); fclose(fp); return -1; }
        }
        else if (strcmp(key, "block_score") == 0)
        {
            if (!parse_score(value, &policy->block_score)) { set_error(error, error_size, "invalid block_score"); fclose(fp); return -1; }
        }
        else if (strcmp(key, "strict") == 0)
        {
            if (!parse_bool(value, &policy->strict)) { set_error(error, error_size, "invalid strict value"); fclose(fp); return -1; }
        }
        else if (strcmp(key, "max_gzip_ratio") == 0)
        {
            if (!parse_double_positive(value, &policy->max_gzip_ratio)) { set_error(error, error_size, "invalid max_gzip_ratio"); fclose(fp); return -1; }
        }
        else if (strcmp(key, "max_tar_entries") == 0)
        {
            if (!parse_u64(value, &policy->max_tar_entries)) { set_error(error, error_size, "invalid max_tar_entries"); fclose(fp); return -1; }
        }
        else if (strcmp(key, "max_image_pixels") == 0)
        {
            if (!parse_u64(value, &policy->max_image_pixels)) { set_error(error, error_size, "invalid max_image_pixels"); fclose(fp); return -1; }
        }
        else if (strcmp(key, "allow_formats") == 0)
        {
            if (!parse_format_list(value, &policy->allow_formats, 1)) { set_error(error, error_size, "invalid allow_formats"); fclose(fp); return -1; }
        }
        else if (strcmp(key, "deny_formats") == 0)
        {
            if (!parse_format_list(value, &policy->deny_formats, 0)) { set_error(error, error_size, "invalid deny_formats"); fclose(fp); return -1; }
        }
        else
        {
            snprintf(error, error_size, "unknown policy key on line %u: %s", line_number, key);
            fclose(fp);
            return -1;
        }
    }
    fclose(fp);
    snprintf(policy->policy_file, sizeof(policy->policy_file), "%s", path);
    return af_policy_validate(policy, error, error_size);
}
