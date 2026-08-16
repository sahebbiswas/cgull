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


@dataclass
class CASTContext:
    functions: List[CFunction]
    global_variables: Dict[str, CVariable]
    source_lines: List[str]
    raw_source: str
    clean_source: str
    has_pycparser: bool = False
    pycparser_ast: Optional[Any] = None


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

        functions = self._extract_functions(clean_lines, clean_code)
        global_vars = self._extract_global_vars(clean_lines, functions)

        pycparser_ast, has_pycparser = self._try_pycparser(clean_code)
        if has_pycparser and pycparser_ast is not None:
            self._merge_pycparser_findings(pycparser_ast, functions)

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

        pycparser requires preprocessed C99 input. We approximate that by
        stripping preprocessor directives and injecting typedefs for the
        standard integer/size types that real C code universally assumes.
        This is not a full preprocessor -- files that rely on macro
        expansion to be syntactically valid will still fail to parse -- but
        it is enough to successfully parse a large fraction of ordinary
        application code, which is what actually matters for the rules
        that consume this AST.
        """
        try:
            from pycparser import c_parser
        except ImportError:
            return None, False

        no_directives = "\n".join(
            "" if _PREPROCESSOR_LINE_RE.match(line) else line
            for line in clean_code.splitlines()
        )
        prepared = _PYCPARSER_PRELUDE + no_directives

        try:
            parser = c_parser.CParser()
            pycparser_ast = parser.parse(prepared, filename='<input>')
            return pycparser_ast, True
        except Exception:
            return None, False

    def _merge_pycparser_findings(self, pycparser_ast, functions: List["CFunction"]) -> None:
        """
        Cross-checks and enriches the regex-derived function list using the
        real pycparser AST. Currently this fixes the most impactful known
        gap in the regex extractor: multi-declarator local variable
        declarations (`int a, b, c;`), which a single-declarator regex
        cannot represent. Variables recovered this way are merged into the
        matching CFunction so every downstream rule (uninitialized-memory,
        VLA, etc.) benefits without any rule-level changes.
        """
        try:
            from pycparser import c_ast
        except ImportError:
            return

        funcs_by_line = {fn.start_line: fn for fn in functions}
        # Also allow matching by name in case brace-counting drifted the
        # start line by a comment/blank-line off-by-one.
        funcs_by_name: Dict[str, List["CFunction"]] = {}
        for fn in functions:
            funcs_by_name.setdefault(fn.name, []).append(fn)

        class _LocalDeclVisitor(c_ast.NodeVisitor):
            def __init__(self, owning_fn: "CFunction", base_line: int):
                self.owning_fn = owning_fn
                self.base_line = base_line

            def visit_Decl(self, node):
                # Skip function prototypes / typedefs / struct-only decls.
                if node.name and node.coord is not None:
                    is_pointer = type(node.type).__name__ == "PtrDecl"
                    is_func = type(node.type).__name__ == "FuncDecl"
                    if not is_func:
                        line_no = node.coord.line - _PRELUDE_LINE_COUNT
                        existing = self.owning_fn.variables.get(node.name)
                        # pycparser is authoritative: prefer it whenever it
                        # disagrees with the regex extractor, since the
                        # regex path is known to occasionally misfire on
                        # bare statements (see _STATEMENT_KEYWORDS) or miss
                        # multi-declarator lines entirely.
                        if existing is None or existing.declaration_line != (line_no if line_no > 0 else self.owning_fn.start_line):
                            self.owning_fn.variables[node.name] = CVariable(
                                name=node.name,
                                type_name=self._type_name(node.type),
                                is_pointer=is_pointer,
                                is_signed="unsigned" not in self._type_name(node.type),
                                is_volatile="volatile" in (node.quals or []),
                                is_vla=False,
                                array_size_expr=None,
                                has_initializer=node.init is not None,
                                declaration_line=line_no if line_no > 0 else self.owning_fn.start_line,
                            )
                self.generic_visit(node)

            @staticmethod
            def _type_name(type_node) -> str:
                names = getattr(type_node, "names", None)
                if names:
                    return " ".join(names)
                inner = getattr(type_node, "type", None)
                if inner is not None:
                    return _LocalDeclVisitor._type_name(inner)
                return "int"

        for ext in pycparser_ast.ext:
            if type(ext).__name__ != "FuncDef":
                continue
            fname = ext.decl.name
            fn_line = (ext.decl.coord.line - _PRELUDE_LINE_COUNT) if ext.decl.coord else None

            owning_fn = None
            if fn_line and fn_line in funcs_by_line:
                owning_fn = funcs_by_line[fn_line]
            elif fname in funcs_by_name and len(funcs_by_name[fname]) == 1:
                owning_fn = funcs_by_name[fname][0]
            if owning_fn is None or ext.body is None:
                continue

            visitor = _LocalDeclVisitor(owning_fn, owning_fn.start_line)
            for stmt in getattr(ext.body, "block_items", None) or []:
                visitor.visit(stmt)

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
