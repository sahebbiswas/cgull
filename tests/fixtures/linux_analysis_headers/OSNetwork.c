#include "project.h"
#include <linux/if.h>
int interface_flags(struct ifreq *request)
{
    return request->ifr_flags;
}
