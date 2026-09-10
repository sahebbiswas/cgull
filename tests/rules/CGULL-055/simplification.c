#if FEATURE || (FEATURE && EXTRA) // expect: CGULL-055
int enabled;
#endif

#if PARENT
#if PARENT && CHILD // expect: CGULL-055
int nested;
#endif
#endif
