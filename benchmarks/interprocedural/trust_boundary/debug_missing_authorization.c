void mailbox_receive(unsigned *); int authenticate_request(unsigned); void debug_enable(unsigned);
void case_main(void) { unsigned v; mailbox_receive(&v); if (!authenticate_request(v)) return; debug_enable(v); }
