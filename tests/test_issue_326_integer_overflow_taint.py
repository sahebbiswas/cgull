from types import SimpleNamespace

from cgull.rules.types_and_arrays.arithmetic_integer_overflow import ArithmeticIntegerOverflowRule


def _scan(body: str, params=()):
    lines = body.splitlines()
    fn = SimpleNamespace(
        body=body,
        start_line=1,
        body_start_line=1,
        parameters=tuple(SimpleNamespace(name=name) for name in params),
    )
    ctx = SimpleNamespace(functions=(fn,), source_lines=lines)
    return ArithmeticIntegerOverflowRule().scan_ast("sample.c", ctx)


def test_reports_fgets_atoi_arithmetic_without_guard():
    issues = _scan(
        "char input[32];\n"
        "int data = 0;\n"
        "fgets(input, sizeof(input), stdin);\n"
        "data = atoi(input);\n"
        "int result = data + 1;\n"
    )
    assert len(issues) == 1
    assert "external input" in issues[0].message
    assert issues[0].line_number == 5


def test_reports_argv_derived_increment():
    issues = _scan(
        "int data = atoi(argv[1]);\n"
        "data++;\n",
        params=("argc", "argv"),
    )
    assert len(issues) == 1
    assert "data++" in issues[0].message


def test_upper_bound_guard_suppresses_tainted_addition():
    issues = _scan(
        "int data = atoi(argv[1]);\n"
        "if (data < 1000) {\n"
        "int result = data + 1;\n"
        "}\n",
        params=("argc", "argv"),
    )
    assert issues == []


def test_lower_bound_only_guard_does_not_suppress_tainted_addition():
    issues = _scan(
        "int data = atoi(argv[1]);\n"
        "if (data > 0) {\n"
        "int result = data + 1;\n"
        "}\n",
        params=("argc", "argv"),
    )
    assert len(issues) == 1
    assert issues[0].line_number == 3


def test_lower_bound_guard_suppresses_tainted_subtraction():
    issues = _scan(
        "int data = atoi(argv[1]);\n"
        "if (data > 0) {\n"
        "int result = data - 1;\n"
        "}\n",
        params=("argc", "argv"),
    )
    assert issues == []


def test_trusted_reassignment_clears_taint():
    issues = _scan(
        "int data = atoi(argv[1]);\n"
        "data = 2;\n"
        "int result = data + 1;\n",
        params=("argc", "argv"),
    )
    assert issues == []


def test_read_buffer_propagates_through_integer_conversion():
    issues = _scan(
        "char input[32];\n"
        "read(fd, input, sizeof(input));\n"
        "int count = strtol(input, 0, 10);\n"
        "int index = count * 2;\n"
    )
    assert len(issues) == 1
    assert issues[0].line_number == 4


def test_tainted_allocation_arithmetic_is_reported_once():
    issues = _scan(
        "int count = atoi(argv[1]);\n"
        "void *p = malloc(count + 1);\n",
        params=("argc", "argv"),
    )
    assert len(issues) == 1
    assert issues[0].line_number == 2
    assert "memory allocation argument" in issues[0].message


def test_for_loop_header_arithmetic_is_not_reported():
    issues = _scan(
        "int len = atoi(argv[1]);\n"
        "for (int i = 0; i < len - 1; i++) {\n"
        "use(i);\n"
        "}\n",
        params=("argc", "argv"),
    )
    assert issues == []
