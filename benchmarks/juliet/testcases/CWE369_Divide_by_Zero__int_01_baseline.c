/* Reduced, self-contained Juliet 1.3 CWE-369 divide-by-zero fixture. */
void CWE369_Divide_by_Zero__int_01_baseline_bad(int divisor) {
    int result = 100 / divisor;
    (void)result;
}

void CWE369_Divide_by_Zero__int_01_baseline_good(int divisor) {
    if (divisor != 0) {
        int result = 100 / divisor;
        (void)result;
    }
}
