/* CGULL-020 Negative Test Suite */

int handle_event(int event_id, void *extra_data) {
    process(extra_data);
    return event_id;
}

int handle_reserved(int event_id, void *__reserved) {
    return event_id;
}

void explicit_unused(int value) {
    (void)value;
}
