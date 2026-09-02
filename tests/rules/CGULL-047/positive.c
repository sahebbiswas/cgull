int external_read(void);
int validate(int);
void sink(int);

void direct_unvalidated(void) {
    int value = external_read();
    sink(value); // expect: CGULL-047
}

void validation_too_late(void) {
    int value = external_read();
    sink(value); // expect: CGULL-047
    (void)validate(value);
}
