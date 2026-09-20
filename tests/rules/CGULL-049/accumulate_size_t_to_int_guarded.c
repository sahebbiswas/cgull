/* Guarded size_t→int conversions must not report (#558 optional acceptance). */

int guarded_before_return(size_t size)
{
    if (size > INT_MAX) {
        return -1;
    }
    return (int)size;
}

int guarded_dominating_then(size_t size)
{
    if (size <= INT_MAX) {
        return (int)size;
    }
    return -1;
}
