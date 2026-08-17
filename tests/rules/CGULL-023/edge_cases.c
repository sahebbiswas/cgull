/* CGULL-023 Edge Cases Test Suite */

/* Uninitialized variable in switch statement without default initialization */
int test_edge_switch_uninit(int mode) {
    int value; // expect: CGULL-023
    switch (mode) {
    case 1:
        value = 10;
        break;
    case 2:
        value = 20;
        break;
    }
    return value;
}
