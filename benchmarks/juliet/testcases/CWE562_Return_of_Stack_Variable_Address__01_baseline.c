void CWE562_Return_of_Stack_Variable_Address__01_baseline_bad(void)
{
    int local = 1;
    return &local;
}

void CWE562_Return_of_Stack_Variable_Address__01_baseline_good(void)
{
    static int local = 1;
    (void)local;
    return;
}
