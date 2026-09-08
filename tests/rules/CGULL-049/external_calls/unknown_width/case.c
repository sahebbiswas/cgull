typedef struct Opaque opaque_t;
void external(opaque_t);
void caller(int n) { external(n); }
