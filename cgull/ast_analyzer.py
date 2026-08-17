"""
AST and Lexical Semantic Analyzer for C code in C-GULL.
Provides both pycparser integration (if installed) and a built-in
lightweight C Abstract Syntax Tree & Semantic Flow Parser.

Design note: pycparser cannot parse raw, unpreprocessed C (it chokes on
#include, macros, and standard-library typedefs like size_t/uint32_t that
it never sees a definition for). Rather than silently degrading to
"pycparser_ast = None" for almost every real-world file -- which is what
happened before, since nothing ever consumed pycparser_ast anyway -- this
module now (a) strips preprocessor directives, (b) injects a small prelude
of the typedefs real C code relies on constantly, and (c) actually walks
the resulting AST with a NodeVisitor to extract precise function/variable
information that the regex-based extractor structurally cannot get right,
most notably multi-declarator lines like `int a, b, c;`. Where pycparser
succeeds, its findings are merged into (and take precedence over) the
regex-derived CFunction/CVariable data; where it fails (which will still
happen on complex real headers/macros), we transparently fall back to the
regex-only extraction exactly as before.
"""

import re
from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional, Set, Tuple

from .utils import strip_comments_keep_lines

# Common standard-library typedefs that pycparser needs a definition for
# since it never sees <stdint.h>/<stddef.h>/etc. Injected as a prelude
# before parsing; stripped back out via line-count offset afterwards.
_PYCPARSER_PRELUDE = """
typedef unsigned long size_t;
typedef long ssize_t;
typedef unsigned char uint8_t;
typedef signed char int8_t;
typedef unsigned short uint16_t;
typedef signed short int16_t;
typedef unsigned int uint32_t;
typedef signed int int32_t;
typedef unsigned long uint64_t;
typedef signed long int64_t;
typedef int wchar_t;
typedef int bool;
typedef unsigned long uintptr_t;
typedef long intptr_t;
typedef unsigned long size_type;
"""
_PRELUDE_LINE_COUNT = _PYCPARSER_PRELUDE.count("\n")

# Keywords that must never be treated as a "type" by the declaration-regex
# matcher. Without this guard, a bare statement like `return c;` or
# `break;` parses as if it were declaring a variable named after whatever
# identifier follows the keyword (`return` looks like a type, `c` looks
# like the declared name), producing spurious "uninitialized variable"
# findings on ordinary control-flow statements.
_STATEMENT_KEYWORDS = {
    'return', 'break', 'continue', 'goto', 'case', 'default', 'if', 'else', 'for', 'while',
    'switch', 'sizeof', 'typeof', 'do',
}

# Strips #include/#define/#pragma/#if.../conditional compilation directives
# (and line-continuations) so pycparser sees plain C. This is a best-effort
# substitute for a real preprocessor pass -- it will not expand macros, so
# code that structurally depends on macro expansion still won't parse, but
# it unblocks the large fraction of files that only use directives for
# includes/include-guards/simple constants.
_PREPROCESSOR_LINE_RE = re.compile(r'^[ \t]*#')


def _strip_attributes_and_specifiers(code: str) -> str:
    """
    Strips GNU/Clang __attribute__((...)) and MSVC __declspec(...) constructs
    from C source code while preserving character/line offsets (replacing
    stripped tokens with spaces/newlines).
    """
    result = []
    i = 0
    n = len(code)
    targets = [('__attribute__', 13), ('__declspec', 10)]
    while i < n:
        matched = False
        for kw, kw_len in targets:
            if code[i:i + kw_len] == kw:
                j = i + kw_len
                while j < n and code[j].isspace():
                    j += 1
                if j < n and code[j] == '(':
                    paren_depth = 0
                    k = j
                    while k < n:
                        if code[k] == '(':
                            paren_depth += 1
                        elif code[k] == ')':
                            paren_depth -= 1
                            if paren_depth == 0:
                                k += 1
                                break
                        k += 1
                    chunk = code[i:k]
                    spaces = ''.join('\n' if c == '\n' else ' ' for c in chunk)
                    result.append(spaces)
                    i = k
                    matched = True
                    break
        if not matched:
            result.append(code[i])
            i += 1
    return ''.join(result)


@dataclass
class CParameter:
    name: str
    type_name: str
    is_pointer: bool
    line_number: int


@dataclass
class CVariable:
    name: str
    type_name: str
    is_pointer: bool
    is_signed: bool
    is_volatile: bool
    is_vla: bool
    array_size_expr: Optional[str]
    has_initializer: bool
    declaration_line: int
    assigned_lines: List[int] = field(default_factory=list)
    read_lines: List[int] = field(default_factory=list)
    freed_lines: List[int] = field(default_factory=list)
    checked_null_lines: List[int] = field(default_factory=list)


@dataclass
class CFGNode:
    node_id: int
    kind: str  # "decl", "assignment", "call", "if_cond", "while_cond", "for_cond", "switch_cond", "return", "free", "null_check", "statement"
    line_number: int
    expr_str: str = ""
    target_var: Optional[str] = None
    read_vars: Set[str] = field(default_factory=set)
    written_vars: Set[str] = field(default_factory=set)
    freed_vars: Set[str] = field(default_factory=set)
    null_checked_vars: Set[str] = field(default_factory=set)
    next_nodes: List["CFGNode"] = field(default_factory=list)


@dataclass
class CFunction:
    name: str
    return_type: str
    parameters: List[CParameter]
    start_line: int
    end_line: int
    body: str
    variables: Dict[str, CVariable] = field(default_factory=dict)
    has_void_param_list: bool = False
    is_empty_param_list: bool = False
    calls: List[Tuple[str, int, str]] = field(default_factory=list)  # (callee_name, line, raw_args)
    returns_boolean: bool = False
    has_assertions: bool = False
    cfg_nodes: List[CFGNode] = field(default_factory=list)


@dataclass
class CASTContext:
    functions: List[CFunction]
    global_variables: Dict[str, CVariable]
    source_lines: List[str]
    raw_source: str
    clean_source: str
    has_pycparser: bool = False
    pycparser_ast: Optional[Any] = None


def _format_pycparser_expr(node) -> str:
    """Recursively formats a pycparser expression node to a C code string."""
    if node is None:
        return ""
    type_name = type(node).__name__
    if type_name == "Constant":
        return str(node.value)
    elif type_name == "ID":
        return str(node.name)
    elif type_name == "UnaryOp":
        return f"{node.op}{_format_pycparser_expr(node.expr)}"
    elif type_name == "BinaryOp":
        return f"{_format_pycparser_expr(node.left)} {node.op} {_format_pycparser_expr(node.right)}"
    elif type_name == "Cast":
        return f"({_format_pycparser_expr(node.to_type)}){_format_pycparser_expr(node.expr)}"
    elif type_name == "ArrayRef":
        return f"{_format_pycparser_expr(node.name)}[{_format_pycparser_expr(node.subscript)}]"
    elif type_name == "StructRef":
        return f"{_format_pycparser_expr(node.name)}{node.type}{_format_pycparser_expr(node.field)}"
    elif type_name == "FuncCall":
        args_str = ""
        if node.args:
            args_str = ", ".join(_format_pycparser_expr(a) for a in getattr(node.args, "exprs", []))
        return f"{_format_pycparser_expr(node.name)}({args_str})"
    elif type_name == "ExprList":
        return ", ".join(_format_pycparser_expr(e) for e in getattr(node, "exprs", []))
    elif type_name == "Typename":
        tname, _, _, _, _, _, _, _ = _format_pycparser_type(node.type)
        return tname
    elif type_name == "Assignment":
        return f"{_format_pycparser_expr(node.lvalue)} {node.op} {_format_pycparser_expr(node.rvalue)}"
    elif type_name == "Decl":
        init_str = f" = {_format_pycparser_expr(node.init)}" if node.init else ""
        return f"{_format_pycparser_expr(node.type)} {node.name}{init_str}"
    elif hasattr(node, "name") and node.name:
        return str(node.name)
    return ""


def _format_pycparser_type(node) -> Tuple[str, bool, bool, bool, bool, bool, Optional[str], bool]:
    """
    Recursively formats a pycparser type node.
    Returns:
      (type_name, is_pointer, is_func_ptr, is_volatile, is_signed, is_vla, array_size_expr, is_array)
    """
    if node is None:
        return "int", False, False, False, True, False, None, False

    quals = getattr(node, "quals", []) or []
    is_volatile = "volatile" in quals
    is_signed = "unsigned" not in quals
    type_name = type(node).__name__

    if type_name == "PtrDecl":
        sub_t, sub_ptr, is_fp, sub_vol, sub_sig, sub_vla, sub_dim, is_arr = _format_pycparser_type(node.type)
        vol = is_volatile or sub_vol
        sig = is_signed and sub_sig
        if is_fp:
            return f"(*{sub_t})", True, True, vol, sig, False, None, False
        return f"{sub_t} *", True, False, vol, sig, False, None, False

    elif type_name == "ArrayDecl":
        sub_t, sub_ptr, sub_fp, sub_vol, sub_sig, _, _, _ = _format_pycparser_type(node.type)
        dim_str = None
        is_vla = False
        if node.dim:
            if type(node.dim).__name__ == "Constant":
                dim_str = str(node.dim.value)
                is_vla = False
            elif type(node.dim).__name__ == "ID":
                dim_str = str(node.dim.name)
                is_vla = True
            else:
                dim_str = _format_pycparser_expr(node.dim)
                is_vla = True
        vol = is_volatile or sub_vol
        sig = is_signed and sub_sig
        return f"{sub_t}[{dim_str or ''}]", sub_ptr, sub_fp, vol, sig, is_vla, dim_str, True

    elif type_name == "FuncDecl":
        ret_t, _, _, sub_vol, sub_sig, _, _, _ = _format_pycparser_type(node.type)
        p_list = []
        if node.args and getattr(node.args, "params", None):
            for p in node.args.params:
                p_type_name = type(p).__name__
                if p_type_name == "Typename":
                    pt, _, _, _, _, _, _, _ = _format_pycparser_type(p.type)
                    p_list.append(pt)
                elif p_type_name == "Decl":
                    pt, _, _, _, _, _, _, _ = _format_pycparser_type(p.type)
                    p_list.append(f"{pt} {p.name}" if getattr(p, "name", None) else pt)
        params_str = ", ".join(p_list) if p_list else "void"
        return f"{ret_t} ({params_str})", False, True, sub_vol, sub_sig, False, None, False

    elif type_name == "TypeDecl":
        inner = node.type
        inner_type_name = type(inner).__name__
        vol = is_volatile
        sig = is_signed
        if inner_type_name == "IdentifierType":
            names = getattr(inner, "names", ["int"])
            tname = " ".join(names)
            if "unsigned" in names:
                sig = False
        elif inner_type_name == "Struct":
            tname = f"struct {inner.name}" if getattr(inner, "name", None) else "struct"
        elif inner_type_name == "Union":
            tname = f"union {inner.name}" if getattr(inner, "name", None) else "union"
        elif inner_type_name == "Enum":
            tname = f"enum {inner.name}" if getattr(inner, "name", None) else "enum"
        else:
            tname = getattr(node, "declname", "int") or "int"
        if "volatile" in (getattr(inner, "quals", []) or []):
            vol = True
        return tname, False, False, vol, sig, False, None, False

    elif type_name == "IdentifierType":
        names = getattr(node, "names", ["int"])
        sig = "unsigned" not in names
        return " ".join(names), False, False, False, sig, False, None, False

    elif type_name == "Typename":
        return _format_pycparser_type(node.type)

    return "int", False, False, False, True, False, None, False


def _extract_identifiers_from_ast(node) -> Set[str]:
    """Recursively extracts all identifier names from an AST node."""
    names: Set[str] = set()
    if node is None:
        return names
    if type(node).__name__ == "ID":
        names.add(str(node.name))
    for _, child in node.children():
        names.update(_extract_identifiers_from_ast(child))
    return names


def _get_max_ast_line(node, current_max: int, prelude_offset: int) -> int:
    """Recursively finds the maximum line coordinate in an AST node."""
    if node is None:
        return current_max
    if getattr(node, "coord", None):
        current_max = max(current_max, node.coord.line - prelude_offset)
    for _, child in node.children():
        current_max = _get_max_ast_line(child, current_max, prelude_offset)
    return current_max


class _ASTFunctionAnalyzer:
    """
    Traverses a pycparser FuncDef body to extract local variables,
    function calls, dataflow events, and CFG nodes.
    """

    def __init__(self, owning_fn: CFunction, prelude_offset: int, clean_lines: List[str]):
        self.owning_fn = owning_fn
        self.prelude_offset = prelude_offset
        self.clean_lines = clean_lines
        self.node_counter = 0

    def analyze(self, body_node) -> None:
        if body_node is None:
            return
        from pycparser import c_ast

        class Visitor(c_ast.NodeVisitor):
            def __init__(self, outer: "_ASTFunctionAnalyzer"):
                self.outer = outer

            def visit_Decl(self, node):
                if node.name and type(node.type).__name__ != "FuncDecl":
                    line_no = (node.coord.line - self.outer.prelude_offset) if node.coord else self.outer.owning_fn.start_line
                    tname, is_ptr, is_fp, is_vol, is_sig, is_vla, arr_dim, _ = _format_pycparser_type(node.type)
                    c_var = CVariable(
                        name=node.name,
                        type_name=tname,
                        is_pointer=(is_ptr or is_fp),
                        is_signed=is_sig,
                        is_volatile=is_vol,
                        is_vla=is_vla,
                        array_size_expr=arr_dim,
                        has_initializer=(node.init is not None),
                        declaration_line=line_no,
                    )
                    init_ids: Set[str] = set()
                    if node.init:
                        c_var.assigned_lines.append(line_no)
                        init_ids = _extract_identifiers_from_ast(node.init)
                        for v in init_ids:
                            if v in self.outer.owning_fn.variables:
                                self.outer.owning_fn.variables[v].read_lines.append(line_no)
                    self.outer.owning_fn.variables[node.name] = c_var

                    init_str = f" = {_format_pycparser_expr(node.init)}" if node.init else ""
                    alloc_fn_names = {"malloc", "calloc", "realloc", "aligned_alloc"}
                    is_alloc = False
                    if node.init:
                        init_expr_str = _format_pycparser_expr(node.init)
                        if any(fn_name in init_expr_str for fn_name in alloc_fn_names):
                            is_alloc = True

                    self.outer.node_counter += 1
                    cfg_n = CFGNode(
                        node_id=self.outer.node_counter,
                        kind="allocation" if is_alloc else "decl",
                        line_number=line_no,
                        expr_str=f"{tname} {node.name}{init_str}",
                        target_var=node.name,
                        written_vars={node.name} if node.init else set(),
                        read_vars=init_ids if node.init else set(),
                    )
                    self.outer.owning_fn.cfg_nodes.append(cfg_n)
                self.generic_visit(node)

            def visit_Assignment(self, node):
                line_no = (node.coord.line - self.outer.prelude_offset) if node.coord else self.outer.owning_fn.start_line
                lval_ids = _extract_identifiers_from_ast(node.lvalue)
                rval_ids = _extract_identifiers_from_ast(node.rvalue)
                target = list(lval_ids)[0] if lval_ids else None
                for v in lval_ids:
                    if v in self.outer.owning_fn.variables:
                        self.outer.owning_fn.variables[v].assigned_lines.append(line_no)
                for v in rval_ids:
                    if v in self.outer.owning_fn.variables:
                        self.outer.owning_fn.variables[v].read_lines.append(line_no)

                alloc_fn_names = {"malloc", "calloc", "realloc", "aligned_alloc"}
                rval_expr_str = _format_pycparser_expr(node.rvalue)
                is_alloc = any(fn_name in rval_expr_str for fn_name in alloc_fn_names)

                self.outer.node_counter += 1
                cfg_n = CFGNode(
                    node_id=self.outer.node_counter,
                    kind="allocation" if is_alloc else "assignment",
                    line_number=line_no,
                    expr_str=f"{_format_pycparser_expr(node.lvalue)} {node.op} {rval_expr_str}",
                    target_var=target,
                    written_vars=lval_ids,
                    read_vars=rval_ids,
                )
                self.outer.owning_fn.cfg_nodes.append(cfg_n)
                self.generic_visit(node)

            def visit_FuncCall(self, node):
                line_no = (node.coord.line - self.outer.prelude_offset) if node.coord else self.outer.owning_fn.start_line
                callee = _format_pycparser_expr(node.name)
                raw_args = _format_pycparser_expr(node.args) if node.args else ""
                if callee not in ('if', 'for', 'while', 'switch', 'sizeof', 'typeof', '__attribute__'):
                    self.outer.owning_fn.calls.append((callee, line_no, raw_args))

                arg_ids = _extract_identifiers_from_ast(node.args) if node.args else set()
                freed_set: Set[str] = set()
                null_checked_set: Set[str] = set()

                param_names = {p.name for p in self.outer.owning_fn.parameters}
                if callee in ("free", "cfree", "vfree", "realloc"):
                    if node.args and getattr(node.args, "exprs", None):
                        freed_p = _format_pycparser_expr(node.args.exprs[0])
                        if freed_p in self.outer.owning_fn.variables or freed_p in param_names:
                            if freed_p in self.outer.owning_fn.variables:
                                self.outer.owning_fn.variables[freed_p].freed_lines.append(line_no)
                            freed_set.add(freed_p)

                if callee in ("assert", "ASSERT", "assert_param"):
                    self.outer.owning_fn.has_assertions = True
                    if node.args:
                        null_checked_set = _extract_identifiers_from_ast(node.args)
                        for v in null_checked_set:
                            if v in self.outer.owning_fn.variables:
                                self.outer.owning_fn.variables[v].checked_null_lines.append(line_no)

                for v in arg_ids:
                    if v in self.outer.owning_fn.variables:
                        self.outer.owning_fn.variables[v].read_lines.append(line_no)

                self.outer.node_counter += 1
                cfg_n = CFGNode(
                    node_id=self.outer.node_counter,
                    kind="free" if freed_set else "call",
                    line_number=line_no,
                    expr_str=f"{callee}({raw_args})",
                    target_var=callee,
                    read_vars=arg_ids,
                    freed_vars=freed_set,
                    null_checked_vars=null_checked_set,
                )
                self.outer.owning_fn.cfg_nodes.append(cfg_n)
                self.generic_visit(node)

            def visit_If(self, node):
                line_no = (node.coord.line - self.outer.prelude_offset) if node.coord else self.outer.owning_fn.start_line
                cond_ids = _extract_identifiers_from_ast(node.cond)
                null_checked_set = set(cond_ids)
                for v in null_checked_set:
                    if v in self.outer.owning_fn.variables:
                        self.outer.owning_fn.variables[v].checked_null_lines.append(line_no)
                for v in cond_ids:
                    if v in self.outer.owning_fn.variables:
                        self.outer.owning_fn.variables[v].read_lines.append(line_no)

                self.outer.node_counter += 1
                cfg_n = CFGNode(
                    node_id=self.outer.node_counter,
                    kind="if_cond",
                    line_number=line_no,
                    expr_str=_format_pycparser_expr(node.cond),
                    read_vars=cond_ids,
                    null_checked_vars=null_checked_set,
                )
                self.outer.owning_fn.cfg_nodes.append(cfg_n)
                self.generic_visit(node)

            def visit_While(self, node):
                line_no = (node.coord.line - self.outer.prelude_offset) if node.coord else self.outer.owning_fn.start_line
                cond_ids = _extract_identifiers_from_ast(node.cond)
                null_checked_set = set(cond_ids)
                for v in null_checked_set:
                    if v in self.outer.owning_fn.variables:
                        self.outer.owning_fn.variables[v].checked_null_lines.append(line_no)
                for v in cond_ids:
                    if v in self.outer.owning_fn.variables:
                        self.outer.owning_fn.variables[v].read_lines.append(line_no)

                self.outer.node_counter += 1
                cfg_n = CFGNode(
                    node_id=self.outer.node_counter,
                    kind="while_cond",
                    line_number=line_no,
                    expr_str=_format_pycparser_expr(node.cond),
                    read_vars=cond_ids,
                    null_checked_vars=null_checked_set,
                )
                self.outer.owning_fn.cfg_nodes.append(cfg_n)
                self.generic_visit(node)

            def visit_For(self, node):
                line_no = (node.coord.line - self.outer.prelude_offset) if node.coord else self.outer.owning_fn.start_line
                cond_ids = _extract_identifiers_from_ast(node.cond) if node.cond else set()
                for v in cond_ids:
                    if v in self.outer.owning_fn.variables:
                        self.outer.owning_fn.variables[v].read_lines.append(line_no)

                self.outer.node_counter += 1
                cfg_n = CFGNode(
                    node_id=self.outer.node_counter,
                    kind="for_cond",
                    line_number=line_no,
                    expr_str=_format_pycparser_expr(node.cond) if node.cond else "",
                    read_vars=cond_ids,
                )
                self.outer.owning_fn.cfg_nodes.append(cfg_n)
                self.generic_visit(node)

            def visit_Return(self, node):
                line_no = (node.coord.line - self.outer.prelude_offset) if node.coord else self.outer.owning_fn.start_line
                ret_expr_str = _format_pycparser_expr(node.expr)
                if ret_expr_str in ("0", "1", "true", "false"):
                    if any(term in self.outer.owning_fn.name.lower() for term in ['auth', 'verify', 'check_password', 'validate_token', 'boot_secure', 'crypto', 'admin', 'login', 'permission']):
                        self.outer.owning_fn.returns_boolean = True

                ret_ids = _extract_identifiers_from_ast(node.expr) if node.expr else set()
                for v in ret_ids:
                    if v in self.outer.owning_fn.variables:
                        self.outer.owning_fn.variables[v].read_lines.append(line_no)

                self.outer.node_counter += 1
                cfg_n = CFGNode(
                    node_id=self.outer.node_counter,
                    kind="return",
                    line_number=line_no,
                    expr_str=ret_expr_str,
                    read_vars=ret_ids,
                )
                self.outer.owning_fn.cfg_nodes.append(cfg_n)
                self.generic_visit(node)

        Visitor(self).visit(body_node)

        # Connect sequential CFG nodes
        for i in range(len(self.owning_fn.cfg_nodes) - 1):
            self.owning_fn.cfg_nodes[i].next_nodes.append(self.owning_fn.cfg_nodes[i + 1])


class CASTParser:
    """
    Lightweight C Abstract Syntax & Semantic Flow Parser.
    Extracts functions, scopes, variables, control flow structures,
    pointer dereferences, and function calls.
    """

    def __init__(self):
        pass

    def parse(self, source_code: str) -> CASTContext:
        lines = source_code.splitlines()
        clean_lines, clean_code = strip_comments_keep_lines(source_code)

        pycparser_ast, has_pycparser = self._try_pycparser(clean_code)
        if has_pycparser and pycparser_ast is not None:
            functions, global_vars = self._build_model_from_ast(pycparser_ast, clean_lines, clean_code)
        else:
            functions = self._extract_functions(clean_lines, clean_code)
            global_vars = self._extract_global_vars(clean_lines, functions)

        return CASTContext(
            functions=functions,
            global_variables=global_vars,
            source_lines=lines,
            raw_source=source_code,
            clean_source=clean_code,
            has_pycparser=has_pycparser,
            pycparser_ast=pycparser_ast,
        )

    @staticmethod
    def strip_only(source_code: str) -> Tuple[List[str], str]:
        """
        Cheap path used by the engine in REGEX-only mode: just returns
        comment-stripped lines/code without the (much more expensive)
        function/variable extraction or pycparser attempt.
        """
        return strip_comments_keep_lines(source_code)

    def _try_pycparser(self, clean_code: str):
        """
        Attempts a real pycparser parse of the (comment-stripped) source.

        Three-tier strategy:

        1. **pcpp + pycparser** (best): Use pcpp to expand #define macros
           and evaluate #ifdef conditionals, then parse with pycparser.
           This handles the common case of macro-dependent code.

        2. **Strip directives + pycparser** (good): If pcpp is unavailable
           or its output still fails to parse, fall back to the original
           approach of stripping preprocessor directives and injecting a
           typedef prelude.

        3. **Regex extractor** (fallback): If pycparser is not installed
           or both tiers above fail, return None and let the caller use
           the regex-based function/variable extractor.
        """
        try:
            from pycparser import c_parser
        except ImportError:
            return None, False

        # Tier 1: pcpp preprocessing (if available)
        pcpp_result = self._try_pcpp_preprocess(clean_code)
        if pcpp_result is not None:
            try:
                parser = c_parser.CParser()
                pycparser_ast = parser.parse(pcpp_result, filename='<input>')
                return pycparser_ast, True
            except Exception:
                pass  # Fall through to tier 2

        # Tier 2: Strip directives + typedef prelude (original approach)
        no_directives = "\n".join(
            "" if _PREPROCESSOR_LINE_RE.match(line) else line
            for line in clean_code.splitlines()
        )
        stripped_code = _strip_attributes_and_specifiers(no_directives)
        prepared = _PYCPARSER_PRELUDE + stripped_code

        try:
            parser = c_parser.CParser()
            pycparser_ast = parser.parse(prepared, filename='<input>')
            return pycparser_ast, True
        except Exception:
            return None, False

    def _try_pcpp_preprocess(self, clean_code: str) -> "Optional[str]":
        """
        Uses pcpp (pure-Python C preprocessor) to expand macros and
        evaluate conditional compilation directives, producing output
        that pycparser can parse.

        Returns the preprocessed source with the typedef prelude
        prepended, or None if pcpp is not installed or preprocessing
        fails.

        Line-number preservation: pcpp emits ``#line N`` directives.
        We convert those back into the appropriate number of blank
        lines so that pycparser's reported line numbers (minus the
        prelude offset) still map to original source lines.
        """
        try:
            import pcpp
        except ImportError:
            return None

        import io
        import re

        class _SilentPreprocessor(pcpp.Preprocessor):
            """Suppresses errors and passes through unresolvable #includes."""
            def on_error(self, file, line, msg):
                pass

            def on_include_not_found(self, is_malformed, is_system_include,
                                     curdir, includepath):
                raise pcpp.OutputDirective(pcpp.Action.IgnoreAndPassThrough)

        try:
            preprocessor = _SilentPreprocessor()
            # Feed the typedef prelude + source as a single unit so that
            # macros defined in the source are expanded while the prelude
            # typedefs are preserved for pycparser.
            combined = _PYCPARSER_PRELUDE + clean_code
            preprocessor.parse(combined, '<input>')
            out = io.StringIO()
            preprocessor.write(out)
            raw = out.getvalue()

            # Reconstruct line-preserving output: convert #line N
            # directives into blank-line padding so that line numbers
            # in the output correspond to line numbers in `combined`.
            line_dir_re = re.compile(r'^#line\s+(\d+)')
            output_lines: list = []
            current_line = 1
            for line in raw.splitlines():
                m = line_dir_re.match(line)
                if m:
                    target_line = int(m.group(1))
                    while current_line < target_line:
                        output_lines.append('')
                        current_line += 1
                else:
                    output_lines.append(line)
                    current_line += 1

            result = '\n'.join(output_lines)

            # Strip any remaining #include lines that pcpp passed through
            # (unresolvable includes) -- pycparser can't handle them.
            result = '\n'.join(
                '' if _PREPROCESSOR_LINE_RE.match(ln) else ln
                for ln in result.splitlines()
            )
            result = _strip_attributes_and_specifiers(result)

            return result
        except Exception:
            return None

    def _build_model_from_ast(
        self, pycparser_ast, clean_lines: List[str], clean_code: str
    ) -> Tuple[List[CFunction], Dict[str, CVariable]]:
        """
        Builds the authoritative structural representation (functions, parameters,
        local/global variables, symbols, types, scopes, CFG, and dataflow)
        directly from a pycparser AST.
        """
        from pycparser import c_ast

        functions: List[CFunction] = []
        global_vars: Dict[str, CVariable] = {}

        for ext in pycparser_ast.ext:
            if isinstance(ext, c_ast.Decl) and type(ext.type).__name__ != "FuncDecl" and type(ext).__name__ != "Typedef":
                line_no = (ext.coord.line - _PRELUDE_LINE_COUNT) if ext.coord else 1
                tname, is_ptr, is_fp, is_vol, is_sig, is_vla, arr_dim, _ = _format_pycparser_type(ext.type)
                if ext.name and ext.name not in ('typedef', '#include', '#define', '#ifdef', '#ifndef'):
                    global_vars[ext.name] = CVariable(
                        name=ext.name,
                        type_name=tname,
                        is_pointer=(is_ptr or is_fp),
                        is_signed=is_sig,
                        is_volatile=is_vol,
                        is_vla=is_vla,
                        array_size_expr=arr_dim,
                        has_initializer=(ext.init is not None),
                        declaration_line=line_no,
                    )

            elif isinstance(ext, c_ast.FuncDef):
                fname = ext.decl.name
                fn_start = (ext.decl.coord.line - _PRELUDE_LINE_COUNT) if ext.decl.coord else 1

                ret_t, _, _, _, _, _, _, _ = _format_pycparser_type(ext.decl.type.type)

                params: List[CParameter] = []
                has_void_param = False
                is_empty_params = False
                func_args = ext.decl.type.args

                if func_args is None or not getattr(func_args, "params", None):
                    is_empty_params = True
                else:
                    if len(func_args.params) == 1:
                        p0 = func_args.params[0]
                        p0_type, _, _, _, _, _, _, _ = _format_pycparser_type(p0.type)
                        if p0_type == "void" and (not getattr(p0, "name", None) or p0.name == "void"):
                            has_void_param = True

                    if not has_void_param:
                        for param in func_args.params:
                            p_name = getattr(param, "name", None) or ""
                            p_type, p_is_ptr, p_is_fp, _, _, _, _, _ = _format_pycparser_type(param.type)
                            p_line = (param.coord.line - _PRELUDE_LINE_COUNT) if param.coord else fn_start
                            params.append(CParameter(
                                name=p_name,
                                type_name=p_type,
                                is_pointer=(p_is_ptr or p_is_fp),
                                line_number=p_line,
                            ))

                fn_end = _get_max_ast_line(ext.body, fn_start, _PRELUDE_LINE_COUNT)
                brace_count = 0
                for l in range(fn_start, len(clean_lines) + 1):
                    line_str = clean_lines[l - 1]
                    brace_count += line_str.count("{") - line_str.count("}")
                    if l >= fn_end and brace_count <= 0:
                        fn_end = l
                        break

                fn_body = "\n".join(clean_lines[fn_start: max(fn_start, fn_end - 1)]) if fn_start < fn_end else ""

                fn = CFunction(
                    name=fname,
                    return_type=ret_t,
                    parameters=params,
                    start_line=fn_start,
                    end_line=fn_end,
                    body=fn_body,
                    has_void_param_list=has_void_param,
                    is_empty_param_list=is_empty_params,
                )

                if ext.body:
                    _ASTFunctionAnalyzer(fn, _PRELUDE_LINE_COUNT, clean_lines).analyze(ext.body)

                functions.append(fn)

        return functions, global_vars

    def _extract_functions(self, lines: List[str], full_code: str) -> List[CFunction]:
        functions: List[CFunction] = []
        # Pattern to match C function header: return_type func_name(params) {
        # e.g., int auth_user(char *user, const char *pass)
        func_header_regex = re.compile(
            r'^[ \t]*((?:(?:static|inline|extern|const|unsigned|signed|struct\s+\w+|\w+)\s+)+)(\*?\s*[\w_]+)\s*\(([^)]*)\)\s*\{',
            re.MULTILINE
        )

        for match in func_header_regex.finditer(full_code):
            start_pos = match.start()
            start_line = full_code[:start_pos].count('\n') + 1

            ret_type = match.group(1).strip()
            raw_name = match.group(2).strip()
            params_str = match.group(3).strip()

            if raw_name.startswith('*'):
                ret_type += ' *'
                func_name = raw_name[1:].strip()
            else:
                func_name = raw_name

            # Skip control structures masquerading as functions if any (e.g. if/while)
            if func_name in ('if', 'for', 'while', 'switch', 'catch'):
                continue

            # Find matching closing brace
            brace_count = 1
            body_start_pos = match.end()
            curr_pos = body_start_pos
            n = len(full_code)

            while curr_pos < n and brace_count > 0:
                ch = full_code[curr_pos]
                if ch == '{':
                    brace_count += 1
                elif ch == '}':
                    brace_count -= 1
                curr_pos += 1

            end_line = full_code[:curr_pos].count('\n') + 1
            body = full_code[body_start_pos:curr_pos - 1]

            # Parse parameters
            params: List[CParameter] = []
            is_empty_params = (params_str == "")
            has_void_param = (params_str == "void")

            if params_str and params_str != "void":
                for param_token in params_str.split(','):
                    param_token = param_token.strip()
                    if not param_token:
                        continue
                    is_ptr = '*' in param_token
                    p_parts = param_token.replace('*', ' * ').split()
                    if len(p_parts) >= 2:
                        p_name = p_parts[-1]
                        p_type = " ".join(p_parts[:-1])
                    elif len(p_parts) == 1:
                        p_name = p_parts[0]
                        p_type = "int"
                    else:
                        continue
                    params.append(CParameter(name=p_name, type_name=p_type, is_pointer=is_ptr, line_number=start_line))

            fn = CFunction(
                name=func_name,
                return_type=ret_type,
                parameters=params,
                start_line=start_line,
                end_line=end_line,
                body=body,
                has_void_param_list=has_void_param,
                is_empty_param_list=is_empty_params,
            )

            # Analyze function body variables & calls
            self._analyze_function_body(fn, lines)
            functions.append(fn)

        return functions

    def _analyze_function_body(self, fn: CFunction, all_lines: List[str]) -> None:
        body_lines = fn.body.splitlines()
        fn_start = fn.start_line

        # Detect assertions
        if "assert(" in fn.body or "ASSERT(" in fn.body or "assert_param(" in fn.body:
            fn.has_assertions = True

        # Detect boolean return in security context
        if re.search(r'\breturn\s+(?:0|1|true|false)\s*;', fn.body):
            if any(term in fn.name.lower() for term in ['auth', 'verify', 'check_password', 'validate_token', 'boot_secure', 'crypto', 'admin', 'login', 'permission']):
                fn.returns_boolean = True

        # Extract function calls inside body
        call_regex = re.compile(r'\b([a-zA-Z_]\w*)\s*\(([^;{}]*)\)')
        for i, line in enumerate(body_lines):
            line_no = fn_start + i
            for match in call_regex.finditer(line):
                callee = match.group(1)
                args = match.group(2)
                if callee not in ('if', 'for', 'while', 'switch', 'sizeof', 'typeof', '__attribute__'):
                    fn.calls.append((callee, line_no, args))

        C_KEYWORDS = {
            'return', 'break', 'continue', 'goto', 'case', 'default', 'if', 'else', 'for', 'while',
            'switch', 'sizeof', 'typeof', 'typedef', 'struct', 'union', 'enum', 'extern', 'static',
            'const', 'volatile', 'register', 'inline', 'restrict', '0', '1', 'NULL'
        }

        # Track local variable declarations
        var_decl_regex = re.compile(
            r'^[ \t]*((?:volatile\s+|static\s+|const\s+|unsigned\s+|signed\s+|struct\s+\w+|\w+)\s+(?:\*|\w|\s)*?)\s*([a-zA-Z_]\w*)(?:\[([^\]]*)\])?(?:\s*=\s*([^;]+))?;'
        )
        for i, line in enumerate(body_lines):
            line_no = fn_start + i
            m = var_decl_regex.match(line)
            if m:
                type_prefix = m.group(1).strip()
                v_name = m.group(2).strip()
                array_dim = m.group(3)
                init_val = m.group(4)

                if v_name in C_KEYWORDS or not v_name.isidentifier():
                    continue
                type_tokens = type_prefix.split()
                if type_tokens and type_tokens[-1] in _STATEMENT_KEYWORDS:
                    # e.g. "return c;" / "break;" mis-parsed as a decl of `c`.
                    continue

                is_ptr = '*' in type_prefix or '*' in v_name
                is_signed = 'unsigned' not in type_prefix
                is_volatile = 'volatile' in type_prefix
                is_vla = False
                if array_dim is not None:
                    dim_clean = array_dim.strip()
                    if dim_clean and not dim_clean.isdigit() and not dim_clean.isupper() and not dim_clean.startswith('0x'):
                        # Array dimension is variable -> VLA
                        is_vla = True

                c_var = CVariable(
                    name=v_name,
                    type_name=type_prefix,
                    is_pointer=is_ptr,
                    is_signed=is_signed,
                    is_volatile=is_volatile,
                    is_vla=is_vla,
                    array_size_expr=array_dim,
                    has_initializer=(init_val is not None),
                    declaration_line=line_no,
                )
                if init_val:
                    c_var.assigned_lines.append(line_no)
                fn.variables[v_name] = c_var

        # Track variable life cycles (free, null-checks, reads, assignments)
        for i, line in enumerate(body_lines):
            line_no = fn_start + i
            # free(x)
            free_match = re.search(r'\bfree\s*\(\s*(\w+)\s*\)', line)
            if free_match:
                v_name = free_match.group(1)
                if v_name in fn.variables:
                    fn.variables[v_name].freed_lines.append(line_no)

            # if (x == NULL) or if (!x) or if (x != NULL)
            for v_name in list(fn.variables.keys()) + [p.name for p in fn.parameters]:
                if re.search(rf'\bif\s*\([^)]*?\b{re.escape(v_name)}\s*(?:==\s*NULL|!=\s*NULL|==\s*0|!=\s*0)\b', line) or \
                   re.search(rf'\bif\s*\(\s*!{re.escape(v_name)}\b', line) or \
                   re.search(rf'\bif\s*\(\s*{re.escape(v_name)}\s*\)', line):
                    if v_name in fn.variables:
                        fn.variables[v_name].checked_null_lines.append(line_no)

    def _extract_global_vars(self, lines: List[str], functions: List[CFunction]) -> Dict[str, CVariable]:
        global_vars: Dict[str, CVariable] = {}
        func_line_ranges = set()
        for fn in functions:
            for l in range(fn.start_line, fn.end_line + 1):
                func_line_ranges.add(l)

        var_decl_regex = re.compile(
            r'^[ \t]*((?:volatile\s+|static\s+|const\s+|unsigned\s+|signed\s+|struct\s+\w+|\w+)\s+(?:\*|\w|\s)*?)\s*(\w+)(?:\[([^\]]*)\])?(?:\s*=\s*([^;]+))?;'
        )

        for line_no, line in enumerate(lines, 1):
            if line_no in func_line_ranges:
                continue
            m = var_decl_regex.match(line)
            if m:
                type_prefix = m.group(1).strip()
                v_name = m.group(2).strip()
                type_tokens = type_prefix.split()
                if type_tokens and type_tokens[-1] in _STATEMENT_KEYWORDS:
                    continue
                if v_name not in ('typedef', '#include', '#define', '#ifdef', '#ifndef'):
                    global_vars[v_name] = CVariable(
                        name=v_name,
                        type_name=type_prefix,
                        is_pointer='*' in type_prefix,
                        is_signed='unsigned' not in type_prefix,
                        is_volatile='volatile' in type_prefix,
                        is_vla=False,
                        array_size_expr=m.group(3),
                        has_initializer=m.group(4) is not None,
                        declaration_line=line_no,
                    )
        return global_vars
