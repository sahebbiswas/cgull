void *malloc(unsigned long size);
void consume_buffer(char *buffer);

void unresolved_call_safe(void) {
    char *buffer = (char *)malloc(8);
    if (buffer == 0) return;
    consume_buffer(buffer);
}
