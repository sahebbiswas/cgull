typedef int *IntPtr;
void escapes(void) {
    int a[10];
    IntPtr p = &a[3];
    IntPtr q = p - 4; // expect: CGULL-050
    IntPtr r = &p[8]; // expect: CGULL-050
    p += 8; // expect: CGULL-050
}
void access(void) {
    char a[4];
    char *p = a + 4;
    char v = *p; // expect: CGULL-050
    p[0] = 1; // expect: CGULL-050
    p -= 5; // expect: CGULL-050
}
