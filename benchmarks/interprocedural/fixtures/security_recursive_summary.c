int second(int);

int first(int value) {
    return second(value);
}

int second(int value) {
    if (value)
        return first(value);
    return value;
}
