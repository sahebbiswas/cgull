void *malloc(unsigned long size);
void free(void *pointer);

static void allocate_output(char **output) {
    *output = (char *)malloc(8);
}

void output_parameter_unsafe(void) {
    char *buffer;
    allocate_output(&buffer);
    buffer[0] = 'x';
    free(buffer);
}
