/* GetArraySize-style accumulate-then-cast-to-int (#558). */

typedef struct Item {
    struct Item *next;
} Item;

int count_items(const Item *head)
{
    const Item *child = head;
    size_t size = 0;

    while (child != NULL) {
        size++;
        child = child->next;
    }

    /* FIXME: Can overflow INT_MAX — mirrors cJSON_GetArraySize. */
    return (int)size; // expect: CGULL-049
}

int count_items_implicit_return(const Item *head)
{
    const Item *child = head;
    size_t size = 0;

    while (child != NULL) {
        size++;
        child = child->next;
    }

    return size; // expect: CGULL-049
}

int cast_size_t_param(size_t size)
{
    return (int)size; // expect: CGULL-049
}
