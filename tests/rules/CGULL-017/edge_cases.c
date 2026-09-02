/* CGULL-017 Edge Cases Test Suite */

void test_edge_nested_switch(int outer, int inner) {
    switch (outer) {
        case 1:
            switch (inner) { // expect: CGULL-017
                case 2: handle_inner(); break;
            }
            break;
        default:
            break;
    }
}

void test_edge_spaced_default(int state) {
    switch (state) {
        case 1: break;
        default : break;
    }
}
