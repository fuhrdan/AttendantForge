#include "policy.h"

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
    snprintf(policy->profile, sizeof(policy->profile), "%s", "desktop");
}

int af_policy_apply_profile(AfPolicy *policy, const char *name, char *error, size_t error_size)
{
    if (policy == NULL || name == NULL) return -1;
    if (strcmp(name, "desktop") == 0)
    {
        policy->warn_score = 60u;
        policy->block_score = 80u;
        policy->strict = 0;
    }
    else if (strcmp(name, "upload-server") == 0)
    {
        policy->warn_score = 45u;
        policy->block_score = 70u;
        policy->strict = 0;
    }
    else if (strcmp(name, "high-security") == 0)
    {
        policy->warn_score = 30u;
        policy->block_score = 60u;
        policy->strict = 1;
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
