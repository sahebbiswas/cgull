/* CGULL-025 Edge Cases Test Suite */

int test_edge_complex_without_assert(int value) { // expect: CGULL-025
    if (value > 0) {
        value += 1;
    }
    if (value > 1) {
        value += 2;
    }
    if (value > 2) {
        value += 3;
    }
    if (value > 3) {
        value += 4;
    }
    if (value > 4) {
        value += 5;
    }
    return value;
}

int test_edge_assert_macro(int value) {
    ASSERT(value >= 0);
    value += 1;
    value += 2;
    value += 3;
    value += 4;
    value += 5;
    value += 6;
    value += 7;
    value += 8;
    value += 9;
    value += 10;
    value += 11;
    value += 12;
    value += 13;
    value += 14;
    value += 15;
    return value;
}
