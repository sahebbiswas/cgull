/* CGULL-025 Positive Test Suite */

int compute_hash_state(int value) { // expect: CGULL-025
    value += 1;
    value *= 2;
    value -= 3;
    value ^= 4;
    value += 5;
    value *= 6;
    value -= 7;
    value ^= 8;
    value += 9;
    value *= 10;
    value -= 11;
    value ^= 12;
    value += 13;
    value *= 14;
    value -= 15;
    value ^= 16;
    return value;
}
