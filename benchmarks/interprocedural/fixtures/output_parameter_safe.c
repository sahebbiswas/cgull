void *malloc(unsigned long size);
void free(void *pointer);

static void allocate_output(char **output) {
    char *buffer = (char *)malloc(8);
    if (buffer == 0) {
        *output = 0;
        return;
    }
    *output = buffer;
}

void output_parameter_safe(void) {
    char *buffer;
    allocate_output(&buffer);
    if (buffer != 0) {
        buffer[0] = 'x';
        free(buffer);
    }
}
