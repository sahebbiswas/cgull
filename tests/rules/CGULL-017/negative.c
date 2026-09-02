/* CGULL-017 Negative Test Suite */

void test_tn_default_present(int state) {
    switch (state) {
        case 1:
            handle_active();
            break;
        default:
            handle_unknown();
            break;
    }
}
