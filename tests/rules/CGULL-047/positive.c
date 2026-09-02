int external_read(void);
void sink(int);

void unsafe_direct(void) {
    int value = external_read();
    sink(value); // expect: CGULL-047
}

int read_wrapper(void) {
    return external_read();
}

void unsafe_wrapper(void) {
    int value = read_wrapper();
    sink(value); // expect: CGULL-047
}
