void *malloc(int);
void *malloc(unsigned int);
void caller(int n) { malloc(n); }
