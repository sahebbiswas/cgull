#if 0 // expect: CGULL-054
int unreachable_configuration;
#endif

#if FEATURE_A
int feature_a;
#elif FEATURE_B
int feature_b;
#endif
