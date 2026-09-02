void *malloc(unsigned long size);
void free(void *pointer);

static void recursive_release(char *buffer, unsigned int depth) {
    if (depth == 0) {
        free(buffer);
        return;
    }
    recursive_release(buffer, depth - 1);
}

void recursion_safe(void) {
    char *buffer = (char *)malloc(8);
    if (buffer == 0) return;
    buffer[0] = 'x';
    recursive_release(buffer, 1);
}
