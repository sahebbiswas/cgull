/* Under fake_libc ``typedef int size_t``, signed→size_t must not report (#558). */

typedef int size_t;

void *malloc(size_t n);

void sink(int data)
{
    if (data < 100) {
        char *buf = (char *)malloc(data);
        (void)buf;
    }
}
