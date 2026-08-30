#include "vulnerable.h"

int main(void) {
    char buf[128];
    unsafe_read(buf);
    return 0;
}
