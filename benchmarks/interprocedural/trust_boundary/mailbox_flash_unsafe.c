void mailbox_receive(unsigned *); void flash_write(unsigned);
void case_main(void) { unsigned v; mailbox_receive(&v); flash_write(v); }
