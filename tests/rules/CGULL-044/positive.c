/* CGULL-044 Positive Test Suite */

struct Packet {
    char payload[100];
    int words[10];
};

void test_tp_struct_member_overflow(struct Packet *packet, const char *source) {
    memcpy(packet->payload, source, 150); // expect: CGULL-044
}

void test_tp_plain_array_overflow(const char *source) {
    char buffer[100];
    memcpy(buffer, source, 120); // expect: CGULL-044
}

void test_tp_nonbyte_array_overflow(struct Packet *packet, const int *source) {
    memcpy(packet->words, source, 50); // expect: CGULL-044
}
