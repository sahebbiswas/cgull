/* CGULL-013 Positive Test Suite */

void test_tp_naked_if(int error) {
    if (error) // expect: CGULL-013
        handle_error();
}

void test_tp_naked_loop(int count) {
    while (count > 0) // expect: CGULL-013
        count--;
}

void test_tp_naked_for(int count) {
    for (int i = 0; i < count; ++i) // expect: CGULL-013
        process(i);
}
