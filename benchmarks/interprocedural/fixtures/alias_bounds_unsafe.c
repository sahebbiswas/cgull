void *memcpy(void *destination, const void *source, unsigned long count);

static void copy_alias(char *destination, const char *source, unsigned long count) {
    memcpy(destination, source, count);
}

void alias_bounds_unsafe(const char *source) {
    char buffer[8];
    char *alias = buffer;
    copy_alias(alias, source, 16);
}
