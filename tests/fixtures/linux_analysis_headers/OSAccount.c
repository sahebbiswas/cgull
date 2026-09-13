#include "project.h"
#include <shadow.h>
long password_age(const char *name)
{
    struct spwd *entry = getspnam(name);
    return entry ? entry->sp_lstchg : -1;
}
