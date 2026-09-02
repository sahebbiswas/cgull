int external_read(void);
void sink(int);

int read_one(void) {
    return external_read();
}

int read_two(void) {
    return read_one();
}

void caller(void) {
    int value = read_two();
    sink(value);
}
