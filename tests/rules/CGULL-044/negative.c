/* CGULL-044 Negative Test Suite */

struct Packet {
    char payload[100];
};

void test_tn_constant_within_capacity(struct Packet *packet, const char *source) {
    memcpy(packet->payload, source, 100);
}

void test_tn_unsigned_size_guard(struct Packet *packet, const char *source, size_t size) {
    if (size <= 100) {
        memcpy(packet->payload, source, size);
    }
}

void test_tn_signed_size_guard(struct Packet *packet, const char *source, int size) {
    if (size >= 0 && size <= 100) {
        memcpy(packet->payload, source, size);
    }
}
