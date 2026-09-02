void dma_descriptor_receive(unsigned *); int validate_bounds(unsigned); int authorize_request(unsigned); void dma_start(unsigned);
void case_main(int gate) { unsigned v; dma_descriptor_receive(&v); while (gate) { if (!validate_bounds(v)) return; if (!authorize_request(v)) return; break; } dma_start(v); }
