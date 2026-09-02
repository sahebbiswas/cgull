void update_manifest_receive(unsigned *); int verify_signature(unsigned); int authorize_request(unsigned); void update_activate(unsigned);
void case_main(void) { unsigned v; update_manifest_receive(&v); if (verify_signature(v) != 0) return; if (!authorize_request(v)) return; update_activate(v); }
