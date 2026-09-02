/* CGULL-002 dedicated precision regression fixture.
 *
 * The original Juliet false positive was a GoodSource/BadSink shape where a
 * local format buffer is provably initialized from a fixed literal before
 * printf(format). These cases keep that distinction explicit while preserving
 * true-positive coverage for attacker-controlled or directive-bearing formats.
 */
#include <stdio.h>
#include <string.h>

void precision_safe_literal_array(void) {
    char format[32] = "fixed string";
    printf(format);
}

void precision_safe_literal_pointer(void) {
    char *format = "fixed string";
    printf(format);
}

void precision_safe_literal_after_read_only_call(void) {
    char format[] = "fixed string";
    (void)strlen(format);
    printf(format);
}

void precision_unsafe_directive_literal_buffer(void) {
    char format[] = "%x %x";
    printf(format); /* expect: CGULL-002 */
}

void precision_unsafe_parameter(char *format) {
    printf(format); /* expect: CGULL-002 */
}

void precision_unsafe_mutated_buffer(char *input) {
    char format[64] = "fixed string";
    strcpy(format, input);
    printf(format); /* expect: CGULL-002 */
}
