/* CGULL-010 Positive Test Suite */

void test_tp_runtime_length(int length) {
    char buffer[length]; // expect: CGULL-010
    use(buffer);
}

void test_tp_expression_length(int rows, int columns) {
    int matrix[rows * columns]; // expect: CGULL-010
    use(matrix);
}
