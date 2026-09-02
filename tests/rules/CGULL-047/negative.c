int external_read(void);
int validate(int);
void sink(int);

void validated_external(void) {
    int value = external_read();
    if (!validate(value))
        return;
    sink(value);
}

void trusted_local(void) {
    int value = 7;
    sink(value);
}
