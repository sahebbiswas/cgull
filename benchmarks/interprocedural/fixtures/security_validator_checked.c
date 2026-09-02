int external_read(void);
int validate(int);
void sink(int);

int check_value(int value) {
    return validate(value);
}

void caller(void) {
    int value = external_read();
    if (!check_value(value))
        return;
    sink(value);
}
