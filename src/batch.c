#ifndef _WIN32
#define _POSIX_C_SOURCE 200809L
#endif
#include "batch.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#ifdef _WIN32
#include <windows.h>
#define PATH_SEP '\\'
#else
#include <dirent.h>
#include <sys/stat.h>
#define PATH_SEP '/'
#endif

static int policy_block(const AfReport *r, const AfPolicy *p)
{
    if (!af_policy_format_allowed(p, r->type)) return 1;
    if (r->type == AF_TYPE_GZIP && p->max_gzip_ratio > 0.0 && r->gzip.expansion_ratio > p->max_gzip_ratio) return 1;
    if (r->type == AF_TYPE_TAR && p->max_tar_entries > 0ull && r->tar.entry_count > p->max_tar_entries) return 1;
    if ((r->type == AF_TYPE_PNG || r->type == AF_TYPE_JPEG) && p->max_image_pixels > 0ull && r->image.pixel_count > p->max_image_pixels) return 1;
    return r->score >= p->block_score;
}
static const char *decision(const AfReport *r,const AfPolicy*p){if(policy_block(r,p))return "BLOCK"; if(r->score>=p->warn_score)return "WARN"; return "ALLOW";}
static void js(FILE *o,const char*s){const unsigned char*p=(const unsigned char*)(s?s:"");fputc('"',o);while(*p){if(*p=='"'||*p=='\\')fputc('\\',o);if(*p=='\n'){fputs("\\n",o);p++;continue;}fputc(*p++,o);}fputc('"',o);}
static void csv(FILE *o,const char*s){const char*p=s?s:"";fputc('"',o);while(*p){if(*p=='"')fputc('"',o);fputc(*p++,o);}fputc('"',o);}
static void emit(FILE *o,AfBatchFormat f,const AfReport*r,const AfPolicy*p)
{
    if(f==AF_BATCH_NDJSON){fputs("{\"file\":",o);js(o,r->path);fprintf(o,",\"type\":\"%s\",\"size_bytes\":%llu,\"score\":%u,\"level\":\"%s\",\"decision\":\"%s\",\"extension_signature_mismatch\":%s,\"notes\":",af_type_name(r->type),(unsigned long long)r->file_size,r->score,af_risk_name(r->level),decision(r,p),r->extension_signature_mismatch?"true":"false");js(o,r->notes);fputs("}\n",o);}
    else if(f==AF_BATCH_CSV){csv(o,r->path);fprintf(o,",%s,%llu,%u,%s,%s,%s,",af_type_name(r->type),(unsigned long long)r->file_size,r->score,af_risk_name(r->level),decision(r,p),r->extension_signature_mismatch?"true":"false");csv(o,r->notes);fputc('\n',o);}
    else { fprintf(o,"%-6s %3u %-8s mismatch=%-3s %s\n",af_type_name(r->type),r->score,decision(r,p),r->extension_signature_mismatch?"yes":"no",r->path); }
}
static void account(AfBatchSummary*s,const AfReport*r,const AfPolicy*p){const char*d=decision(r,p);s->scanned++;if(r->type<8)s->by_type[r->type]++;if(r->score>s->highest_score)s->highest_score=r->score;if(r->extension_signature_mismatch)s->mismatches++;if(!strcmp(d,"BLOCK"))s->blocked++;else if(!strcmp(d,"WARN"))s->warned++;else s->allowed++;}
static int scan_one(const char*path,FILE*out,AfBatchFormat fmt,const AfPolicy*p,AfBatchSummary*s){AfReport r;s->files_seen++;if(af_scan_file(path,&r)!=0){s->errors++;return 0;}account(s,&r,p);emit(out,fmt,&r,p);return 0;}
#ifndef _WIN32
static int walk(const char*dir,int rec,FILE*out,AfBatchFormat fmt,const AfPolicy*p,AfBatchSummary*s){DIR*d=opendir(dir);struct dirent*e;if(!d)return -1;while((e=readdir(d))){char path[4096];struct stat st;if(!strcmp(e->d_name,".")||!strcmp(e->d_name,".."))continue;snprintf(path,sizeof(path),"%s/%s",dir,e->d_name);if(lstat(path,&st)!=0){s->errors++;continue;}if(S_ISLNK(st.st_mode))continue;if(S_ISDIR(st.st_mode)){if(rec)walk(path,rec,out,fmt,p,s);}else if(S_ISREG(st.st_mode))scan_one(path,out,fmt,p,s);}closedir(d);return 0;}
#else
static int walk(const char*dir,int rec,FILE*out,AfBatchFormat fmt,const AfPolicy*p,AfBatchSummary*s){WIN32_FIND_DATAA fd;HANDLE h;char spec[4096];snprintf(spec,sizeof(spec),"%s\\*",dir);h=FindFirstFileA(spec,&fd);if(h==INVALID_HANDLE_VALUE)return -1;do{char path[4096];if(!strcmp(fd.cFileName,".")||!strcmp(fd.cFileName,".."))continue;snprintf(path,sizeof(path),"%s\\%s",dir,fd.cFileName);if(fd.dwFileAttributes&FILE_ATTRIBUTE_REPARSE_POINT)continue;if(fd.dwFileAttributes&FILE_ATTRIBUTE_DIRECTORY){if(rec)walk(path,rec,out,fmt,p,s);}else scan_one(path,out,fmt,p,s);}while(FindNextFileA(h,&fd));FindClose(h);return 0;}
#endif
int af_batch_scan(const char*path,int recursive,AfBatchFormat fmt,const char*outpath,const AfPolicy*p,AfBatchSummary*s){FILE*out=stdout;int rc;memset(s,0,sizeof(*s));if(outpath&&strcmp(outpath,"-")!=0){out=fopen(outpath,"w");if(!out)return -2;}if(fmt==AF_BATCH_CSV)fputs("file,type,size_bytes,score,level,decision,extension_signature_mismatch,notes\n",out);rc=walk(path,recursive,out,fmt,p,s);if(out!=stdout)fclose(out);return rc;}
