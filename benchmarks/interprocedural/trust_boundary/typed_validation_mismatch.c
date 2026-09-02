void mailbox_receive(unsigned *); int authenticate_request(unsigned); void flash_write(unsigned);
void case_main(void) { unsigned v; mailbox_receive(&v); if (!authenticate_request(v)) return; flash_write(v); }
