void mailbox_receive(unsigned *); int validate_bounds(unsigned); int authorize_request(unsigned); void flash_write(unsigned);
unsigned read_external(void) { unsigned v; mailbox_receive(&v); return v; }
void case_main(void) { unsigned v = read_external(); if (!validate_bounds(v)) return; if (!authorize_request(v)) return; flash_write(v); }
