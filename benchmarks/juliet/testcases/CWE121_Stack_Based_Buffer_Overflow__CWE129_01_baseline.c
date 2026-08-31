/* Reduced, self-contained Juliet 1.3 CWE-121/CWE-129 bounds fixture. */
void CWE121_Stack_Based_Buffer_Overflow__CWE129_01_baseline_bad(void) {
    char data[10] = "";
    data[10] = 'A';
}

void CWE121_Stack_Based_Buffer_Overflow__CWE129_01_baseline_good(void) {
    char data[10] = "";
    data[9] = 'A';
}
