/* CGULL-020 Positive Test Suite */

int handle_event(int event_id, void *extra_data) { // expect: CGULL-020
    return event_id;
}

void log_message(int level, const char *message) { // expect: CGULL-020
    write_log(message);
}
