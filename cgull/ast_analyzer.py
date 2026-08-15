"""
AST and Lexical Semantic Analyzer for C code in C-GULL.
Provides both pycparser integration (if installed) and a built-in
lightweight C Abstract Syntax Tree & Semantic Flow Parser.
"""

import re
from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional, Set, Tuple


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
        clean_lines, clean_code = self._strip_comments_keep_lines(source_code)

        functions = self._extract_functions(clean_lines, clean_code)
        global_vars = self._extract_global_vars(clean_lines, functions)

        # Pycparser attempt if available
        pycparser_ast = None
        has_pycparser = False
        try:
            from pycparser import c_parser
            parser = c_parser.CParser()
            # Pycparser requires basic C99 preprocessed input
            pycparser_ast = parser.parse(clean_code, filename='<input>')
            has_pycparser = True
        except Exception:
            has_pycparser = False
            pycparser_ast = None

        return CASTContext(
            functions=functions,
            global_variables=global_vars,
            source_lines=lines,
            raw_source=source_code,
            clean_source=clean_code,
            has_pycparser=has_pycparser,
            pycparser_ast=pycparser_ast,
        )

    def _strip_comments_keep_lines(self, source: str) -> Tuple[List[str], str]:
        """
        Strips block comments /* */ and line comments // while preserving
        exact line breaks and string literals.
        """
        output_chars = []
        i = 0
        n = len(source)
        in_string = False
        in_char = False
        in_line_comment = False
        in_block_comment = False

        while i < n:
            c = source[i]
            next_c = source[i + 1] if i + 1 < n else ""

            if in_line_comment:
                if c == "\n":
                    in_line_comment = False
                    output_chars.append("\n")
                else:
                    output_chars.append(" ")
                i += 1
                continue

            if in_block_comment:
                if c == "*" and next_c == "/":
                    in_block_comment = False
                    output_chars.append("  ")
                    i += 2
                elif c == "\n":
                    output_chars.append("\n")
                    i += 1
                else:
                    output_chars.append(" ")
                    i += 1
                continue

            if in_string:
                output_chars.append(c)
                if c == "\\" and i + 1 < n:
                    output_chars.append(source[i + 1])
                    i += 2
                    continue
                elif c == '"':
                    in_string = False
                i += 1
                continue

            if in_char:
                output_chars.append(c)
                if c == "\\" and i + 1 < n:
                    output_chars.append(source[i + 1])
                    i += 2
                    continue
                elif c == "'":
                    in_char = False
                i += 1
                continue

            if c == "/" and next_c == "/":
                in_line_comment = True
                output_chars.append("  ")
                i += 2
                continue

            if c == "/" and next_c == "*":
                in_block_comment = True
                output_chars.append("  ")
                i += 2
                continue

            if c == '"':
                in_string = True
                output_chars.append(c)
                i += 1
                continue

            if c == "'":
                in_char = True
                output_chars.append(c)
                i += 1
                continue

            output_chars.append(c)
            i += 1

        clean_code = "".join(output_chars)
        clean_lines = clean_code.splitlines()
        return clean_lines, clean_code

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
