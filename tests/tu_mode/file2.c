#include "vulnerable.h"
#include "circ_a.h"

void process_data(void) {
    char buffer[64];
    unsafe_read(buffer);
    circ_a_fn();
}
