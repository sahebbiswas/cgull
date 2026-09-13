#include "project.h"
#include <pthread.h>
int start_thread(void *(*entry)(void *), void *argument)
{
    pthread_attr_t attr;
    pthread_t thread;
    pthread_attr_init(&attr);
    return pthread_create(&thread, &attr, entry, argument);
}
