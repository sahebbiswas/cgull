#include <stdio.h>

int compute(void) {
    return 42;
}

void test_dead_store_initialization(void) {
    int status = compute(); // expect: CGULL-042
    status = 0;             // expect: CGULL-042
}

void test_live_store_then_dead_reassignment(void) {
    int val = 10;
    printf("%d\n", val);
    val = 20;               // expect: CGULL-042
}

void test_volatile_exclusion(void) {
    volatile int v_var = 1;
    v_var = 2;
}

void test_address_taken_exclusion(void) {
    int addr_var = 5;
    int *p = &addr_var;
    addr_var = 10;
    printf("%d\n", *p);
}

void test_conditional_read(int cond) {
    int x = compute();
    if (cond) {
        printf("%d\n", x);
    }
}

/* #554: mutually exclusive arms assign x; join read must not be dead. */
void test_if_else_join_live(int cond) {
    int x;
    if (cond) {
        x = 1;
    } else {
        x = 2;
    }
    printf("%d\n", x);      // live after join — no CGULL-042 on either arm
}

/* #554: true dead store (overwrite before any read) still reported. */
void test_true_dead_overwrite(void) {
    int x;
    x = 1;                  // expect: CGULL-042
    x = 2;
    printf("%d\n", x);
}
