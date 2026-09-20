/* CGULL-011 Negative Test Suite */

typedef void (*event_handler_t)(int);

void handle_event(int event) {
    (void)event;
}

void test_tn_typed_function_pointer(void) {
    event_handler_t callback = handle_event;
    callback(1);
}

/* MACRO(type) declarator must not be treated as a function-pointer cast (#552) */
#define EXPORT(type) type
EXPORT(int) export_foo(void);
EXPORT(void *) export_bar(unsigned long n);
