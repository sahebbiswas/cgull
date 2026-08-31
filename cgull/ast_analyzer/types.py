"""C declaration, type, and structure model helpers."""

import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set, Tuple, Union

from ..models import ParserStatus, ParseTier
from .configuration import is_unsigned_type
from .preprocessor import _eval_c_prep_tokens, _parse_c_int_literal, _tokenize_c_prep_expr

@dataclass
class CParameter:
    name: str
    type_name: str
    is_pointer: bool
    line_number: int
    is_array: bool = False


class ScopedVarDict(dict):
    """
    A custom dictionary for function variables that supports tuple keys (var_name, enclosing_block_id)
    or string keys (var_name) for lexical block-scoping while maintaining backward-compatible
    string key lookups (returning innermost binding) and de-duplicated string key iteration.
    """
    def __getitem__(self, key):
        if super().__contains__(key):
            return super().__getitem__(key)
        if isinstance(key, str):
            for dict_key, var in reversed(list(super().items())):
                if dict_key == key or (isinstance(dict_key, tuple) and dict_key[0] == key):
                    return var
        raise KeyError(key)

    def get(self, key, default=None):
        try:
            return self[key]
        except KeyError:
            return default

    def __contains__(self, key):
        if super().__contains__(key):
            return True
        if isinstance(key, str):
            return any(
                dict_key == key or (isinstance(dict_key, tuple) and dict_key[0] == key)
                for dict_key in super().keys()
            )
        return False

    def items(self):
        seen_names = set()
        for dict_key, var in reversed(list(super().items())):
            name = dict_key[0] if isinstance(dict_key, tuple) else dict_key
            if name not in seen_names:
                seen_names.add(name)
                yield name, var

    def keys(self):
        for name, _var in self.items():
            yield name


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
    is_array: bool = False
    assigned_lines: List[int] = field(default_factory=list)
    read_lines: List[int] = field(default_factory=list)
    freed_lines: List[int] = field(default_factory=list)
    checked_null_lines: List[int] = field(default_factory=list)
    enclosing_block_id: int = 0
    address_taken: bool = False
    address_taken_lines: List[int] = field(default_factory=list)


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


def _map_line(exp_line: int, line_map: Optional[Dict[int, Any]]) -> int:
    if line_map and exp_line in line_map:
        src_loc = line_map[exp_line]
        if isinstance(src_loc, int):
            return src_loc
        if hasattr(src_loc, "line_number"):
            return src_loc.line_number
        if hasattr(src_loc, "line"):
            return src_loc.line
    return exp_line


@dataclass
class CFunction:
    name: str
    return_type: str
    parameters: List[CParameter]
    start_line: int
    end_line: int
    body: str
    variables: Dict[Union[str, Tuple[str, int]], CVariable] = field(default_factory=ScopedVarDict)
    has_void_param_list: bool = False
    is_empty_param_list: bool = False
    calls: List[Tuple[str, int, str]] = field(default_factory=list)  # (callee_name, line, raw_args)
    returns_boolean: bool = False
    has_assertions: bool = False
    cfg_nodes: List[CFGNode] = field(default_factory=list)
    body_start_line: int = 0
    start_line_exp: int = 0
    end_line_exp: int = 0


@dataclass
class FieldInfo:
    """
    Represents a single field inside a C struct or union definition.

    Attributes:
        name: Name of the field.
        type_name: Declared type of the field (e.g. "int", "char", "struct Inner").
        is_array: True if the field is declared as an array (e.g., char buf[100]).
        array_size: Resolved constant element count if compile-time constant or macro;
            None if scalar, flexible array member (data[] or data[0]), or unknown size.
        is_pointer: True if the field is a pointer.
        is_struct_or_union: True if the field type is a nested struct or union.
        nested_tag: Tag name or typedef name of the nested struct/union if applicable.
        is_union: True if the field itself is a union.
    """
    name: str
    type_name: str
    is_array: bool = False
    array_size: Optional[int] = None
    array_dims: List[Optional[int]] = field(default_factory=list)
    is_pointer: bool = False
    is_struct_or_union: bool = False
    nested_tag: Optional[str] = None
    is_union: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "type_name": self.type_name,
            "is_array": self.is_array,
            "array_size": self.array_size,
            "array_dims": self.array_dims,
            "is_pointer": self.is_pointer,
            "is_struct_or_union": self.is_struct_or_union,
            "nested_tag": self.nested_tag,
            "is_union": self.is_union,
        }


@dataclass
class StructDef:
    """
    Represents a C struct or union definition and its field schema table.

    Attributes:
        name: Struct or union tag or primary typedef name.
        is_union: True if this definition is a union rather than a struct.
        fields: Dict mapping field names to FieldInfo objects.
    """
    name: str
    is_union: bool = False
    fields: Dict[str, FieldInfo] = field(default_factory=dict)

    def __getitem__(self, field_name: str) -> FieldInfo:
        return self.fields[field_name]

    def __contains__(self, field_name: str) -> bool:
        return field_name in self.fields

    def __iter__(self):
        return iter(self.fields)

    def __len__(self) -> int:
        return len(self.fields)

    def get(self, field_name: str, default=None):
        return self.fields.get(field_name, default)

    def keys(self):
        return self.fields.keys()

    def values(self):
        return self.fields.values()

    def items(self):
        return self.fields.items()

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "is_union": self.is_union,
            "fields": {k: v.to_dict() for k, v in self.fields.items()},
        }


@dataclass
class TypedefShape:
    """
    Tracks typedef target type, pointer status, array status, and array size.
    """
    target: str
    is_pointer: bool = False
    is_array: bool = False
    array_size: Optional[int] = None


def get_type_byte_size(type_str: str, ast_ctx: Optional["CASTContext"] = None) -> Optional[int]:
    """
    Returns the byte size of a C type string if it is a primitive scalar type or pointer.
    Returns None if the type is a struct, union, or unknown layout.
    """
    if not type_str:
        return None

    tn = type_str.strip()
    tn = re.sub(r'\[[^\]]*\]', '', tn).strip()

    if '*' in tn:
        return 8

    if ast_ctx and hasattr(ast_ctx, 'typedef_shapes') and ast_ctx.typedef_shapes:
        clean_tag = re.sub(r'^(?:const|volatile|struct|union)\s+', '', tn).strip()
        if clean_tag in ast_ctx.typedef_shapes:
            shape = resolve_typedef_shape(clean_tag, ast_ctx.typedef_shapes)
            if shape.is_pointer:
                return 8
            tn = shape.target.strip()
            tn = re.sub(r'\[[^\]]*\]', '', tn).strip()
            if '*' in tn:
                return 8

    tn_lower = re.sub(r'\b(?:const|volatile)\b', '', tn).strip().lower()
    tn_lower = re.sub(r'\s+', ' ', tn_lower)

    if tn_lower in ('char', 'signed char', 'unsigned char', 'int8_t', 'uint8_t', 'void', 'bool', '_bool'):
        return 1
    if tn_lower in ('short', 'signed short', 'unsigned short', 'short int', 'signed short int', 'unsigned short int', 'int16_t', 'uint16_t', 'char16_t'):
        return 2
    if tn_lower in ('int', 'signed int', 'unsigned int', 'signed', 'unsigned', 'int32_t', 'uint32_t', 'float', 'char32_t', 'wchar_t'):
        return 4
    if tn_lower in ('long', 'signed long', 'unsigned long', 'long int', 'signed long int', 'unsigned long int', 'long long', 'signed long long', 'unsigned long long', 'long long int', 'signed long long int', 'unsigned long long int', 'int64_t', 'uint64_t', 'double', 'long double', 'size_t', 'ssize_t', 'intptr_t', 'uintptr_t', 'ptrdiff_t', 'time_t'):
        return 8

    return None


def resolve_typedef_shape(
    type_name: str,
    typedef_shapes: Dict[str, TypedefShape],
    visited: Optional[Set[str]] = None
) -> TypedefShape:
    """
    Recursively resolves typedef shape chains (pointers, arrays, target struct tags/types).
    """
    if visited is None:
        visited = set()

    clean_type = re.sub(r'^(?:const|volatile|struct|union)\s+', '', type_name.strip()).rstrip(' *').strip()
    if not clean_type or clean_type in visited or clean_type not in typedef_shapes:
        return TypedefShape(target=type_name)

    visited.add(clean_type)
    shape = typedef_shapes[clean_type]
    sub = resolve_typedef_shape(shape.target, typedef_shapes, visited)

    is_pointer = shape.is_pointer or sub.is_pointer or ('*' in type_name)
    is_array = shape.is_array or sub.is_array
    array_size = shape.array_size if shape.array_size is not None else sub.array_size

    return TypedefShape(
        target=sub.target,
        is_pointer=is_pointer,
        is_array=is_array,
        array_size=array_size,
    )


@dataclass
class CASTContext:
    functions: List[CFunction]
    global_variables: Dict[str, CVariable]
    source_lines: List[str]
    raw_source: str
    clean_source: str
    has_pycparser: bool = False
    pycparser_ast: Optional[Any] = None
    parser_status: str = ParserStatus.FALLBACK_PARSER.value
    parse_tier: str = ParseTier.REGEX_FALLBACK.value
    unsigned_typedefs: Set[str] = field(default_factory=set)
    struct_defs: Dict[str, StructDef] = field(default_factory=dict)
    typedef_shapes: Dict[str, TypedefShape] = field(default_factory=dict)
    line_map: Optional[Dict[int, Any]] = None

    def _clean_and_resolve_type_string(self, type_str: str) -> Optional[StructDef]:
        if not type_str or not isinstance(type_str, str):
            return None
        tn = type_str.strip()
        if tn in self.struct_defs:
            return self.struct_defs[tn]

        # 1. Clean out array brackets, e.g. [100], [4], []
        cleaned = re.sub(r'\[[^\]]*\]', '', tn)
        # 2. Clean out paren pointer declarators like (*parr) or (*)
        cleaned = re.sub(r'\(\s*\*\s*[a-zA-Z_]\w*\s*\)', '', cleaned)
        cleaned = re.sub(r'\(\s*\*\s*\)', '', cleaned)
        # 3. Strip CV qualifiers, storage specifiers
        cleaned = re.sub(r'\b(?:const|volatile|restrict|static|extern|inline|register)\b', '', cleaned)
        # 4. Strip pointer asterisks and trim
        cleaned = cleaned.replace('*', '').strip()
        # 5. Clean leading struct/union keyword
        tag_candidate = re.sub(r'^(?:struct|union)\s+', '', cleaned).strip()

        # Try candidates in order: if type_str explicitly specifies struct or union,
        # prioritize tag-qualified candidates over unqualified typedef names.
        is_explicit_struct = "struct " in type_str
        is_explicit_union = "union " in type_str

        if is_explicit_struct:
            candidates = [f"struct {tag_candidate}", tag_candidate, cleaned, f"union {tag_candidate}"]
        elif is_explicit_union:
            candidates = [f"union {tag_candidate}", tag_candidate, cleaned, f"struct {tag_candidate}"]
        else:
            candidates = [tag_candidate, cleaned, f"struct {tag_candidate}", f"union {tag_candidate}"]

        for cand in candidates:
            if cand in self.struct_defs:
                return self.struct_defs[cand]

        # 6. Try recursive typedef resolution via typedef_shapes if available
        if tag_candidate in self.typedef_shapes:
            shape = resolve_typedef_shape(tag_candidate, self.typedef_shapes)
            sub_clean = re.sub(r'^(?:const|volatile|struct|union)\s+', '', shape.target.strip()).replace('*', '').strip()
            for cand in [sub_clean, shape.target, f"struct {sub_clean}", f"union {sub_clean}"]:
                if cand in self.struct_defs:
                    return self.struct_defs[cand]

        return None

    def get_struct_def(self, type_name: str) -> Optional[StructDef]:
        if not type_name:
            return None
        return self._clean_and_resolve_type_string(type_name)

    def resolve_struct_def(
        self,
        fn_or_type: Union[CFunction, CVariable, CParameter, str],
        expr_or_var: Optional[str] = None
    ) -> Optional[StructDef]:
        """
        Resolves an expression or base identifier (parameter, local variable, or global)
        within a function (or a direct type string / variable object) to its underlying
        struct or union definition (StructDef by tag or primary typedef).
        """
        # If passed a CVariable or CParameter directly
        if isinstance(fn_or_type, (CVariable, CParameter)):
            return self._clean_and_resolve_type_string(fn_or_type.type_name)

        # If passed a type string or identifier string directly without function context
        if isinstance(fn_or_type, str) and expr_or_var is None:
            return self._clean_and_resolve_type_string(fn_or_type)

        # If passed a function and variable/expression name
        if isinstance(fn_or_type, CFunction):
            fn = fn_or_type
            if not expr_or_var:
                return None
            target_str = expr_or_var.strip()

            # 0. Check for leading type cast in target_str, e.g. "((struct A *)p)->array_a" or "(A_t *)p"
            m_cast = re.search(r'\(\s*\*?\s*\(\s*((?:const\s+|volatile\s+|struct\s+|union\s+)?[a-zA-Z_]\w*(?:\s*\*+)?)\s*\)', target_str)
            if not m_cast:
                m_cast = re.search(r'\(\s*((?:const\s+|volatile\s+|struct\s+|union\s+)?[a-zA-Z_]\w*(?:\s*\*+)?)\s*\)', target_str)
            if m_cast:
                cast_type = m_cast.group(1).strip()
                resolved_cast = self._clean_and_resolve_type_string(cast_type)
                if resolved_cast:
                    return resolved_cast

            # Find matching variable, parameter, or global
            target_type_name: Optional[str] = None

            # 1. Exact variable lookup in function body
            if target_str in fn.variables:
                v = fn.variables[target_str]
                target_type_name = v.type_name
            else:
                # 2. Exact parameter lookup
                for p in fn.parameters:
                    if p.name == target_str:
                        target_type_name = p.type_name
                        break

            # 3. Exact global variable lookup
            if not target_type_name and target_str in self.global_variables:
                target_type_name = self.global_variables[target_str].type_name

            # 4. If target_str is a complex expression (e.g. "a->array_a", "arr[0]", "(*parr)"),
            # extract candidate identifier tokens and search for matching local/param/global
            if not target_type_name:
                idents = re.findall(r'\b[a-zA-Z_]\w*\b', target_str)
                keywords = {'struct', 'union', 'const', 'volatile', 'sizeof', 'return', 'int', 'char', 'void'}
                for ident in idents:
                    if ident in keywords:
                        continue
                    if ident in fn.variables:
                        target_type_name = fn.variables[ident].type_name
                        break
                    for p in fn.parameters:
                        if p.name == ident:
                            target_type_name = p.type_name
                            break
                    if target_type_name:
                        break
                    if ident in self.global_variables:
                        target_type_name = self.global_variables[ident].type_name
                        break

            # 5. Fallback: if not found as variable/param/global, treat target_str as type string
            if not target_type_name:
                target_type_name = target_str

            return self._clean_and_resolve_type_string(target_type_name)

        # Fallback for direct string lookup with expr_or_var
        if isinstance(expr_or_var, str):
            return self._clean_and_resolve_type_string(expr_or_var)
        if isinstance(fn_or_type, str):
            return self._clean_and_resolve_type_string(fn_or_type)

        return None

    def infer_expr_type(self, node: Any, fn: Optional[CFunction] = None) -> Optional[str]:
        """
        Infers the C type string of a pycparser AST expression node,
        resolving struct/union members and array indices.
        """
        if node is None:
            return None
            
        node_type = type(node).__name__
        if node_type == 'ID':
            var_name = node.name
            if fn and var_name in fn.variables:
                return fn.variables[var_name].type_name
            if fn:
                for p in fn.parameters:
                    if p.name == var_name:
                        return p.type_name
            if var_name in self.global_variables:
                return self.global_variables[var_name].type_name
            return None
        elif node_type == 'Cast':
            from ..ast_analyzer import _format_pycparser_expr
            return _format_pycparser_expr(node.to_type)
        elif node_type == 'UnaryOp':
            if node.op == '&':
                sub_t = self.infer_expr_type(node.expr, fn)
                return f"{sub_t} *" if sub_t else "void *"
            elif node.op == '*':
                sub_t = self.infer_expr_type(node.expr, fn)
                if sub_t:
                    sub_t = sub_t.strip()
                    if sub_t.endswith('*'):
                        return sub_t[:-1].strip()
            return None
        elif node_type == 'ArrayRef':
            base_t = self.infer_expr_type(node.name, fn)
            if base_t:
                base_t = base_t.strip()
                if base_t.endswith(']'):
                    return re.sub(r'\[[^\]]*\]$', '', base_t).strip()
                elif base_t.endswith('*'):
                    return base_t[:-1].strip()
                else:
                    if base_t in self.typedef_shapes:
                        shape = resolve_typedef_shape(base_t, self.typedef_shapes)
                        if shape.is_array or shape.is_pointer:
                            return shape.target
            return None
        elif node_type == 'StructRef':
            base_t = self.infer_expr_type(node.name, fn)
            if not base_t:
                return None
            struct_def = self.resolve_struct_def(base_t)
            if struct_def:
                field_name = getattr(node.field, 'name', None)
                if field_name and field_name in struct_def.fields:
                    f_info = struct_def.fields[field_name]
                    base_type = f_info.type_name
                    if getattr(f_info, 'is_pointer', False):
                        return f"{base_type} *"
                    if getattr(f_info, 'is_array', False):
                        dim = f_info.array_dims[0] if getattr(f_info, 'array_dims', None) else (f_info.array_size if getattr(f_info, 'array_size', None) else '')
                        return f"{base_type} [{dim}]"
                    return base_type
            return None
        return None

def split_c_statements_at_outer_depth(code_block: str) -> List[str]:
    """
    Splits a C code block (e.g. struct/union body) into statements on semicolons,
    only at outer depth (brace_depth == 0, paren_depth == 0, bracket_depth == 0).
    """
    statements = []
    current = []
    brace_depth = 0
    paren_depth = 0
    bracket_depth = 0

    for ch in code_block:
        if ch == '{':
            brace_depth += 1
            current.append(ch)
        elif ch == '}':
            brace_depth = max(0, brace_depth - 1)
            current.append(ch)
        elif ch == '(':
            paren_depth += 1
            current.append(ch)
        elif ch == ')':
            paren_depth = max(0, paren_depth - 1)
            current.append(ch)
        elif ch == '[':
            bracket_depth += 1
            current.append(ch)
        elif ch == ']':
            bracket_depth = max(0, bracket_depth - 1)
            current.append(ch)
        elif ch == ';' and brace_depth == 0 and paren_depth == 0 and bracket_depth == 0:
            stmt = ''.join(current).strip()
            if stmt:
                statements.append(stmt)
            current = []
        else:
            current.append(ch)

    stmt = ''.join(current).strip()
    if stmt:
        statements.append(stmt)

    return statements


def parse_member_declarations(stmt: str, clean_code: str) -> List[FieldInfo]:
    """
    Parses a struct/union member declaration statement (e.g. "int a, b[10], *c;")
    extracting type specifiers and splitting declarators on top-level commas.
    """
    stmt = stmt.strip()
    if not stmt or stmt.startswith('#'):
        return []

    m_body_struct = re.match(r'^((?:struct|union)\b[^{}]*\{[^{}]*\}\s*\*?)\s*(.+)$', stmt, re.DOTALL)
    if m_body_struct:
        type_spec = m_body_struct.group(1).strip()
        decl_part = m_body_struct.group(2).strip()
        declarators = [decl_part]
    else:
        tokens = []
        curr = []
        paren_d = 0
        bracket_d = 0
        brace_d = 0
        for ch in stmt:
            if ch == '(': paren_d += 1
            elif ch == ')': paren_d = max(0, paren_d - 1)
            elif ch == '[': bracket_d += 1
            elif ch == ']': bracket_d = max(0, bracket_d - 1)
            elif ch == '{': brace_d += 1
            elif ch == '}': brace_d = max(0, brace_d - 1)

            if ch == ',' and paren_d == 0 and bracket_d == 0 and brace_d == 0:
                tokens.append(''.join(curr).strip())
                curr = []
            else:
                curr.append(ch)
        if curr:
            tokens.append(''.join(curr).strip())

        if not tokens:
            return []

        first_tok = tokens[0]

        # Check for function pointer declarator in first_tok: e.g. "int (*callback)(void *, int)"
        m_fn_first = re.search(r'^(.*?)\(\s*\*\s*([a-zA-Z_]\w*)\s*\)\s*\((.*?)\)$', first_tok)
        if m_fn_first:
            type_spec = m_fn_first.group(1).strip()
            declarators = tokens
        else:
            m_decl_start = re.search(r'\b([a-zA-Z_]\w*)\s*(?::\s*[^:]+)?\s*(?:\[[^\]]*\])?$', first_tok)
            if not m_decl_start:
                return []

            ident_match = m_decl_start.group(1)
            c_type_keywords = {'int', 'char', 'short', 'long', 'float', 'double', 'signed', 'unsigned', 'struct', 'union', 'enum', 'void', 'const', 'volatile', 'bool'}
            if ident_match in c_type_keywords and ':' in first_tok[m_decl_start.start():]:
                # Anonymous bit-field like "unsigned int : 2"
                return []

            decl1_start_idx = m_decl_start.start()
            before_name = first_tok[:decl1_start_idx].rstrip()
            type_spec = before_name.rstrip(' *').strip()
            if not type_spec and ident_match in c_type_keywords:
                type_spec = ident_match
            ptr_stars = before_name[len(type_spec):]

            decl_part1 = (ptr_stars + first_tok[decl1_start_idx:]).strip()
            declarators = [decl_part1] + tokens[1:]

    fields: List[FieldInfo] = []
    for decl_str in declarators:
        decl_str = decl_str.strip()
        if not decl_str:
            continue

        # Check for function pointer member: e.g. "int (*callback)(void *, int)"
        m_fn = re.search(r'^(.*?)\(\s*\*\s*([a-zA-Z_]\w*)\s*\)\s*\((.*?)\)$', decl_str)
        if m_fn:
            ret_t = m_fn.group(1).strip() or type_spec
            f_name = m_fn.group(2).strip()
            params_t = m_fn.group(3).strip()
            fn_type_name = f"{ret_t} (*)({params_t})".strip() if params_t else f"{ret_t} (*)".strip()
            fields.append(FieldInfo(
                name=f_name,
                type_name=fn_type_name,
                is_array=False,
                array_size=None,
                is_pointer=True,
                is_struct_or_union=False,
                nested_tag=None,
                is_union=False,
            ))
            continue

        m_bit = re.search(r'^(.*?)\b([a-zA-Z_]\w*)\s*:\s*([^:]+)$', decl_str)
        if m_bit:
            f_name = m_bit.group(2)
            ptr_part = m_bit.group(1)
            is_ptr = ('*' in ptr_part) or ('*' in type_spec)
            is_array = False
            array_size = None
        else:
            is_ptr = ('*' in decl_str) or ('*' in type_spec)

            m_arr = re.search(r'\b([a-zA-Z_]\w*)\s*\[\s*([^\]]*)\s*\]$', decl_str)
            m_scalar = re.search(r'\b([a-zA-Z_]\w*)$', decl_str)

            if m_arr:
                f_name = m_arr.group(1)
                dim_expr = m_arr.group(2).strip()
                is_array = True
                if dim_expr == "" or dim_expr == "0":
                    array_size = None
                else:
                    array_size = resolve_constant_expr(dim_expr, clean_code)
            elif m_scalar:
                f_name = m_scalar.group(1)
                is_array = False
                array_size = None
            else:
                continue

        is_struct_or_union = False
        nested_tag = None
        is_field_union = False
        if type_spec.startswith('struct ') or type_spec.startswith('union '):
            is_struct_or_union = True
            is_field_union = type_spec.startswith('union ')
            m_t = re.search(r'\b(?:struct|union)\s+([a-zA-Z_]\w*)', type_spec)
            nested_tag = m_t.group(1) if m_t else None

        base_t = type_spec.strip()
        if is_ptr:
            type_name = base_t if base_t.endswith('*') else f"{base_t} *"
        else:
            type_name = base_t

        fields.append(FieldInfo(
            name=f_name,
            type_name=type_name,
            is_array=is_array,
            array_size=array_size,
            is_pointer=is_ptr,
            is_struct_or_union=is_struct_or_union,
            nested_tag=nested_tag,
            is_union=is_field_union,
        ))

    return fields


def resolve_constant_expr(expr_str: str, clean_code: str, max_depth: int = 20) -> Optional[int]:
    """
    Resolves a constant expression string (digit, hex, expression-valued macro #define,
    const int variable, or enum constant) to an integer value if compile-time constant,
    else returns None. Recursively expands object-like macros with cycle protection.
    """
    if not expr_str or not expr_str.strip():
        return None

    s = expr_str.strip()

    # Direct integer literal (e.g. 100, 0x64, 0144)
    m_num = re.match(r'^-?(?:0[xX][0-9a-fA-F]+|0[bB][01]+|\d+)[uUlL]*$', s)
    if m_num:
        parsed_int = _parse_c_int_literal(s)
        if parsed_int is not None:
            return parsed_int

    # Collect object-like macros (#define MACRO body) from clean_code
    macro_defs: Dict[str, str] = {}
    for line in clean_code.splitlines():
        line_s = line.strip()
        if line_s.startswith('#'):
            dir_body = line_s.lstrip('#').strip()
            m_def = re.match(r'^define\s+([a-zA-Z_]\w*)(?!\()\s+(.+)$', dir_body)
            if m_def:
                m_name = m_def.group(1)
                m_val = re.sub(r'/\*.*?\*/|//.*', '', m_def.group(2)).strip()
                if m_val:
                    macro_defs[m_name] = m_val

    # Collect const int variables
    for const_m in re.finditer(
        r'\bconst\s+(?:int|size_t|uint\w+_t|int\w+_t|unsigned\s+int|long|short)\s+([a-zA-Z_]\w*)\s*=\s*([^;]+);',
        clean_code
    ):
        c_name = const_m.group(1)
        c_val = const_m.group(2).strip()
        macro_defs[c_name] = c_val

    # Collect enum constants
    enum_regex = re.compile(r'\benum\b[^{}]*\{([^}]+)\}')
    for enum_m in enum_regex.finditer(clean_code):
        enum_body = enum_m.group(1)
        curr_val = 0
        for item in enum_body.split(','):
            item = item.strip()
            if not item:
                continue
            if '=' in item:
                parts = item.split('=', 1)
                e_name = parts[0].strip()
                e_val_str = parts[1].strip()
                parsed_e = _parse_c_int_literal(e_val_str)
                if parsed_e is not None:
                    curr_val = parsed_e
                else:
                    curr_val = 0
            else:
                e_name = item.strip()
            if e_name and e_name.isidentifier():
                macro_defs[e_name] = str(curr_val)
                curr_val += 1

    # Recursive macro replacement with cycle protection
    def expand_expr(target_str: str, visited: Set[str], depth: int = 0) -> str:
        if depth > max_depth:
            return target_str

        def replace_ident(m):
            ident = m.group(0)
            if ident in macro_defs and ident not in visited:
                new_visited = visited | {ident}
                body = macro_defs[ident]
                return f"({expand_expr(body, new_visited, depth + 1)})"
            return ident

        return re.sub(r'\b[a-zA-Z_]\w*\b', replace_ident, target_str)

    expanded = expand_expr(s, set())

    # Ensure all identifiers in expression are resolved before evaluating
    remaining_idents = set(re.findall(r'\b[a-zA-Z_]\w*\b', expanded)) - {"true", "false"}
    if remaining_idents:
        return None

    numeric_macros: Dict[str, int] = {}
    tokens = _tokenize_c_prep_expr(expanded, numeric_macros)
    if tokens:
        try:
            val = _eval_c_prep_tokens(tokens)
            return val
        except Exception:
            pass

    return None


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
    elif type_name == "Return":
        return f"return {_format_pycparser_expr(node.expr)}".strip() if node.expr else "return"
    elif type_name == "Decl":
        init_str = f" = {_format_pycparser_expr(node.init)}" if node.init else ""
        return f"{_format_pycparser_expr(node.type)} {node.name}{init_str}"
    elif hasattr(node, "name") and node.name:
        return str(node.name)
    return ""


def _format_pycparser_type(node, custom_typedefs: Optional[Set[str]] = None) -> Tuple[str, bool, bool, bool, bool, bool, Optional[str], bool]:
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
        sub_t, sub_ptr, is_fp, sub_vol, sub_sig, sub_vla, sub_dim, is_arr = _format_pycparser_type(node.type, custom_typedefs)
        vol = is_volatile or sub_vol
        sig = is_signed and sub_sig
        if is_fp:
            return f"(*{sub_t})", True, True, vol, sig, False, None, False
        return f"{sub_t} *", True, False, vol, sig, False, None, False

    elif type_name == "ArrayDecl":
        sub_t, sub_ptr, sub_fp, sub_vol, sub_sig, _, _, _ = _format_pycparser_type(node.type, custom_typedefs)
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
        ret_t, _, _, sub_vol, sub_sig, _, _, _ = _format_pycparser_type(node.type, custom_typedefs)
        p_list = []
        if node.args and getattr(node.args, "params", None):
            for p in node.args.params:
                p_type_name = type(p).__name__
                if p_type_name == "EllipsisParam" or not hasattr(p, "type"):
                    p_list.append("...")
                elif p_type_name == "Typename":
                    pt, _, _, _, _, _, _, _ = _format_pycparser_type(p.type, custom_typedefs)
                    p_list.append(pt)
                elif p_type_name == "Decl":
                    pt, _, _, _, _, _, _, _ = _format_pycparser_type(p.type, custom_typedefs)
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
            sig = not is_unsigned_type(tname, custom_typedefs)
        elif inner_type_name == "Struct":
            tname = f"struct {inner.name}" if getattr(inner, "name", None) else "struct"
        elif inner_type_name == "Union":
            tname = f"union {inner.name}" if getattr(inner, "name", None) else "union"
        elif inner_type_name == "Enum":
            tname = f"enum {inner.name}" if getattr(inner, "name", None) else "enum"
        else:
            tname = getattr(node, "declname", "int") or "int"
            sig = not is_unsigned_type(tname, custom_typedefs)
        if "volatile" in (getattr(inner, "quals", []) or []):
            vol = True
        return tname, False, False, vol, sig, False, None, False

    elif type_name == "IdentifierType":
        names = getattr(node, "names", ["int"])
        tname = " ".join(names)
        sig = not is_unsigned_type(tname, custom_typedefs)
        return tname, False, False, False, sig, False, None, False

    elif type_name == "Typename":
        return _format_pycparser_type(node.type, custom_typedefs)

    return "int", False, False, False, True, False, None, False


def _extract_identifiers_from_ast(node, ignore_callees: bool = False) -> Set[str]:
    """Recursively extracts all identifier names from an AST node."""
    names: Set[str] = set()
    if node is None:
        return names
    kind = type(node).__name__
    if kind == "ID":
        names.add(str(node.name))
    elif ignore_callees and kind == "FuncCall":
        if node.args:
            names.update(_extract_identifiers_from_ast(node.args, ignore_callees=ignore_callees))
        return names
    for _, child in node.children():
        names.update(_extract_identifiers_from_ast(child, ignore_callees=ignore_callees))
    return names


def _extract_read_vars_from_ast(node) -> Set[str]:
    """
    Recursively extracts variable identifier names that are read in an AST node,
    properly ignoring struct/union member names in StructRef (s.field or ptr->field).
    For FuncCall nodes, recurses into node.name (to capture function pointer variable reads
    such as fp(), obj->fp(), or callbacks[i]()) as well as node.args.
    """
    names: Set[str] = set()
    if node is None:
        return names
    kind = type(node).__name__
    if kind == "ID":
        names.add(str(node.name))
    elif kind == "StructRef":
        names.update(_extract_read_vars_from_ast(node.name))
        return names
    elif kind == "FuncCall":
        if node.name:
            names.update(_extract_read_vars_from_ast(node.name))
        if node.args:
            names.update(_extract_read_vars_from_ast(node.args))
        return names

    for _, child in node.children():
        names.update(_extract_read_vars_from_ast(child))
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


