// expect: CGULL-045
#ifndef TEST_INCLUSION_GUARD_PARTIAL_H
#define TEST_INCLUSION_GUARD_PARTIAL_H
int my_func(void);
#else
int bad;
#endif
