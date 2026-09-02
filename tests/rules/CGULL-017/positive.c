/* CGULL-017 Positive Test Suite */

void test_tp_missing_default(int state) {
    switch (state) { // expect: CGULL-017
        case 0:
            handle_idle();
            break;
        case 1:
            handle_active();
            break;
    }
}

void test_tp_single_case(int state) {
    switch (state) { // expect: CGULL-017
        case 1: handle_active(); break;
    }
}
