int *CWE562_Return_of_Stack_Variable_Address__02_ifelse_bad(void)
{
    int flag = 1;
    int local = 1;
    if (flag) {
        return &local;
    } else {
        return 0;
    }
}

int *CWE562_Return_of_Stack_Variable_Address__02_ifelse_good(void)
{
    int flag = 1;
    static int local = 1;
    if (flag) {
        return &local;
    } else {
        return 0;
    }
}
