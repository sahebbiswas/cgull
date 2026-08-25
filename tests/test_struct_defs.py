"""
Tests for C-GULL struct/union field-size table (F1).
"""

from cgull.ast_analyzer import CASTParser, FieldInfo, StructDef


def test_acceptance_criteria_struct_defs():
    code = """
    struct Inner { char inner_buf[16]; };
    struct A {
        int id;
        char array_a[100];
        struct Inner in;
        struct Inner *in_ptr;
    };
    typedef struct A A_t;
    """
    parser = CASTParser()
    ctx = parser.parse(code)

    # 1. Independent lookup keys "A", "A_t", "struct A"
    sd_a = ctx.get_struct_def("A")
    sd_a_t = ctx.get_struct_def("A_t")
    sd_struct_a = ctx.get_struct_def("struct A")

    assert sd_a is not None
    assert sd_a is sd_a_t
    assert sd_a is sd_struct_a

    # Direct dict indexing independence
    assert ctx.struct_defs["A"] is ctx.struct_defs["A_t"]

    # 2. Field assertions for struct A / A_t
    # array_a -> array, size 100
    field_array_a = sd_a["array_a"]
    assert field_array_a.is_array is True
    assert field_array_a.array_size == 100

    # in -> nested struct, tag Inner
    field_in = sd_a["in"]
    assert field_in.is_struct_or_union is True
    assert field_in.is_pointer is False
    assert field_in.nested_tag == "Inner"

    # in_ptr -> pointer to struct, tag Inner
    field_in_ptr = sd_a["in_ptr"]
    assert field_in_ptr.is_struct_or_union is True
    assert field_in_ptr.is_pointer is True
    assert field_in_ptr.nested_tag == "Inner"

    # 3. Field assertions for Inner
    sd_inner = ctx.get_struct_def("Inner")
    assert sd_inner is not None
    field_inner_buf = sd_inner["inner_buf"]
    assert field_inner_buf.is_array is True
    assert field_inner_buf.array_size == 16


def test_tagged_inline_typedef():
    code = """
    typedef struct TaggedStruct {
        int val;
    } TaggedAlias_t;
    """
    parser = CASTParser()
    ctx = parser.parse(code)

    sd_tag = ctx.get_struct_def("TaggedStruct")
    sd_struct_tag = ctx.get_struct_def("struct TaggedStruct")
    sd_alias = ctx.get_struct_def("TaggedAlias_t")

    assert sd_tag is not None
    assert sd_tag is sd_struct_tag
    assert sd_tag is sd_alias
    assert sd_tag["val"].type_name in ("int", "int val")


def test_pointer_typedef_fields():
    code = """
    struct Node { int data; };
    typedef struct Node *NodePtr_t;
    typedef int *IntPtr_t;

    struct Wrapper {
        NodePtr_t node_p;
        IntPtr_t int_p;
    };
    """
    parser = CASTParser()
    ctx = parser.parse(code)

    sd = ctx.get_struct_def("Wrapper")
    assert sd is not None

    p1 = sd["node_p"]
    assert p1.is_pointer is True
    assert p1.is_struct_or_union is True
    assert p1.nested_tag == "Node"

    p2 = sd["int_p"]
    assert p2.is_pointer is True
    assert p2.is_struct_or_union is False


def test_array_typedef_fields():
    code = """
    typedef char Buffer32_t[32];

    struct Header {
        int magic;
        Buffer32_t buf;
    };
    """
    parser = CASTParser()
    ctx = parser.parse(code)

    sd = ctx.get_struct_def("Header")
    assert sd is not None

    f = sd["buf"]
    assert f.is_array is True
    assert f.array_size == 32


def test_array_dimension_constant_resolution():
    code = """
    #define BUF_SIZE 64
    #define MULT 2
    #define COMP_LEN (BUF_SIZE * MULT)
    const int CONST_LEN = 32;

    struct Config {
        char buf1[BUF_SIZE];
        char buf2[CONST_LEN];
        char buf3[COMP_LEN];
    };
    """
    parser = CASTParser()
    ctx = parser.parse(code)

    sd = ctx.get_struct_def("Config")
    assert sd is not None

    assert sd["buf1"].is_array is True
    assert sd["buf1"].array_size == 64

    assert sd["buf2"].is_array is True
    assert sd["buf2"].array_size == 32

    assert sd["buf3"].is_array is True
    assert sd["buf3"].array_size == 128


def test_flexible_array_members():
    code = """
    struct Flex1 {
        int length;
        char data[];
    };
    struct Flex2 {
        int count;
        char items[0];
    };
    """
    parser = CASTParser()
    ctx = parser.parse(code)

    sd1 = ctx.get_struct_def("Flex1")
    assert sd1 is not None
    assert sd1["data"].is_array is True
    assert sd1["data"].array_size is None

    sd2 = ctx.get_struct_def("Flex2")
    assert sd2 is not None
    assert sd2["items"].is_array is True
    assert sd2["items"].array_size is None


def test_unions_and_anonymous_typedefs():
    code = """
    union Variant {
        int i_val;
        float f_val;
        char str_val[32];
    };

    typedef struct {
        int code;
        char message[128];
    } Error_t;
    """
    parser = CASTParser()
    ctx = parser.parse(code)

    sd_union = ctx.get_struct_def("Variant")
    assert sd_union is not None
    assert sd_union.is_union is True
    assert sd_union["str_val"].is_array is True
    assert sd_union["str_val"].array_size == 32

    sd_anon = ctx.get_struct_def("Error_t")
    assert sd_anon is not None
    assert sd_anon.is_union is False
    assert sd_anon["message"].is_array is True
    assert sd_anon["message"].array_size == 128


def test_fallback_regex_parser_struct_defs():
    code = """
    struct Inner { char inner_buf[16]; };
    struct A {
        int id;
        char array_a[100];
        struct Inner in;
        struct Inner *in_ptr;
    };
    typedef struct A A_t;

    typedef struct TaggedStruct { int val; } TaggedAlias_t;
    typedef struct Inner *InnerPtr_t;
    typedef char Buffer32_t[32];

    struct Container {
        InnerPtr_t ptr;
        Buffer32_t buf;
    };
    """
    parser = CASTParser()
    struct_defs = parser._extract_struct_defs_from_regex(code)

    assert "A" in struct_defs
    assert "A_t" in struct_defs
    assert struct_defs["A"] is struct_defs["A_t"]

    sd_a = struct_defs["A"]
    assert sd_a["array_a"].is_array is True
    assert sd_a["array_a"].array_size == 100
    assert sd_a["in"].is_struct_or_union is True
    assert sd_a["in"].nested_tag == "Inner"
    assert sd_a["in_ptr"].is_pointer is True
    assert sd_a["in_ptr"].nested_tag == "Inner"

    assert "TaggedStruct" in struct_defs
    assert "TaggedAlias_t" in struct_defs
    assert struct_defs["TaggedStruct"] is struct_defs["TaggedAlias_t"]

    sd_c = struct_defs["Container"]
    assert sd_c["ptr"].is_pointer is True
    assert sd_c["ptr"].is_struct_or_union is True
    assert sd_c["ptr"].nested_tag == "Inner"
    assert sd_c["buf"].is_array is True
    assert sd_c["buf"].array_size == 32


def test_struct_def_dict_methods():
    sd = StructDef(name="TestStruct", fields={
        "a": FieldInfo(name="a", type_name="int"),
        "b": FieldInfo(name="b", type_name="char", is_array=True, array_size=10),
    })

    assert len(sd) == 2
    assert "a" in sd
    assert "b" in sd
    assert "c" not in sd
    assert sd["a"].type_name == "int"
    assert sd.get("b").array_size == 10
    assert sd.get("c") is None
    assert list(sd.keys()) == ["a", "b"]
    assert len(list(sd.values())) == 2
    assert len(list(sd.items())) == 2

    d = sd.to_dict()
    assert d["name"] == "TestStruct"
    assert "fields" in d
    assert d["fields"]["a"]["name"] == "a"
