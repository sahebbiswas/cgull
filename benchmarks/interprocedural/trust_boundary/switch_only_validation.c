void uart_receive(unsigned *); int validate_bounds(unsigned); int check_allowlist(unsigned); void mmio_write(unsigned,unsigned);
void case_main(int mode) { unsigned off; uart_receive(&off); switch (mode) { case 1: if (!validate_bounds(off)) return; if (!check_allowlist(off)) return; break; default: break; } mmio_write(off, 0); }
