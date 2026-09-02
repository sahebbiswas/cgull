void *malloc(unsigned long size);
void free(void *pointer);

static void recursive_release(char *buffer, unsigned int depth) {
    if (depth == 0) {
        free(buffer);
        return;
    }
    recursive_release(buffer, depth - 1);
}

void recursion_unsafe(void) {
    char *buffer = (char *)malloc(8);
    if (buffer == 0) return;
    recursive_release(buffer, 1);
    buffer[0] = 'x';
}
