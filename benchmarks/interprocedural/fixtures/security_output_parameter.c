void external_out(int *);
void sink(int);

void read_value(int *out) {
    external_out(out);
}

void caller(void) {
    int value = 0;
    read_value(&value);
    sink(value);
}
