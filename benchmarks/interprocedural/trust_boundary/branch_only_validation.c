void mailbox_receive(unsigned *); int validate_bounds(unsigned); int authorize_request(unsigned); void flash_write(unsigned);
void case_main(int gate) { unsigned v; mailbox_receive(&v); if (gate) { if (!validate_bounds(v)) return; if (!authorize_request(v)) return; } flash_write(v); }
