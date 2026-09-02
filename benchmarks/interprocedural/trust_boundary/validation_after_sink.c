void mailbox_receive(unsigned *); int validate_bounds(unsigned); int authorize_request(unsigned); void flash_write(unsigned);
void case_main(void) { unsigned v; mailbox_receive(&v); flash_write(v); validate_bounds(v); authorize_request(v); }
