/* C-GULL parsing model; not an ABI definition. */
#ifndef CGULL_ANALYSIS_DLFCN_H
#define CGULL_ANALYSIS_DLFCN_H
#include <stddef.h>
typedef struct {
    const char *dli_fname;
    void *dli_fbase;
    const char *dli_sname;
    void *dli_saddr;
} Dl_info;
int dladdr(const void *address, Dl_info *info);
void *dlopen(const char *filename, int flags);
void *dlsym(void *handle, const char *symbol);
int dlclose(void *handle);
char *dlerror(void);
#endif
