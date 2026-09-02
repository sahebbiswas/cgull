void *malloc(unsigned long size);
void consume_buffer(char *buffer);

void unresolved_call_unsafe(void) {
    char *buffer = (char *)malloc(8);
    consume_buffer(buffer);
}
