static void read_name(const char *fmt, char *dst) {
    scanf(fmt, dst);
}

void data_dependent_scanf_unsafe(char *dst) {
    read_name("%s", dst);
}
