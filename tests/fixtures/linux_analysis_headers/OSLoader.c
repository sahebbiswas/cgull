#include "project.h"
#include <dlfcn.h>
int locate_symbol(const void *address)
{
    Dl_info info;
    return dladdr(address, &info);
}
