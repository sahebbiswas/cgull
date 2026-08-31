"""pycparser traversal and lexical AST parsing."""

import logging
import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Mapping, Optional, Set, Tuple, Union

from ..models import ParserStatus, ParseTier
from ..utils import mask_string_and_char_literals, strip_comments_keep_lines
from .configuration import *
from .configuration import _PRELUDE_LINE_COUNT, _PREPROCESSOR_LINE_RE, _PYCPARSER_PRELUDE
from .preprocessor import *
from .preprocessor import _normalize_macro_dict, _strip_attributes_and_specifiers
from .configuration import _STATEMENT_KEYWORDS
from .types import  _format_pycparser_expr, _format_pycparser_type, _extract_identifiers_from_ast, _extract_read_vars_from_ast, _get_max_ast_line
from .types import (
    CASTContext, CFunction, CParameter, CVariable, CFGNode, FieldInfo,
    ScopedVarDict, StructDef, TypedefShape, _map_line, parse_member_declarations,
    resolve_constant_expr, resolve_typedef_shape, split_c_statements_at_outer_depth,
)

logger = logging.getLogger(__name__)

class _ASTFunctionAnalyzer:
    """
    Traverses a pycparser FuncDef body to extract local variables,
    function calls, dataflow events, and CFG nodes.
    """

    def __init__(self, owning_fn: CFunction, prelude_offset: int, clean_lines: List[str], custom_typedefs: Optional[Set[str]] = None, typedef_shapes: Optional[Dict[str, TypedefShape]] = None, line_map: Optional[Dict[int, Any]] = None):
        self.owning_fn = owning_fn
        self.prelude_offset = prelude_offset
        self.clean_lines = clean_lines
        self.custom_typedefs = custom_typedefs
        self.typedef_shapes = typedef_shapes or {}
        self.line_map = line_map
        self.node_counter = 0
        self.block_counter = 0
        self.scope_stack: List[int] = [0]
        self.block_parents: Dict[int, int] = {}

    def resolve_var(self, name: str) -> Optional[CVariable]:
        for block_id in reversed(self.scope_stack):
            var_key = (name, block_id)
            if var_key in self.owning_fn.variables:
                return self.owning_fn.variables[var_key]
        if name in self.owning_fn.variables:
            return self.owning_fn.variables[name]
        return None

    def analyze(self, body_node) -> None:
        if body_node is None:
            return
        from pycparser import c_ast

        class Visitor(c_ast.NodeVisitor):
            def __init__(self, outer: "_ASTFunctionAnalyzer"):
                self.outer = outer
                self.current_target_var: Optional[str] = None

            def visit_Compound(self, node):
                parent_id = self.outer.scope_stack[-1]
                self.outer.block_counter += 1
                block_id = self.outer.block_counter
                self.outer.block_parents[block_id] = parent_id
                self.outer.scope_stack.append(block_id)
                self.generic_visit(node)
                self.outer.scope_stack.pop()

            def visit_Decl(self, node):
                prev_target = self.current_target_var
                if node.name and type(node.type).__name__ != "FuncDecl":
                    self.current_target_var = node.name
                    exp_line = (node.coord.line - self.outer.prelude_offset) if node.coord else self.outer.owning_fn.start_line_exp
                    line_no = _map_line(exp_line, self.outer.line_map)
                    tname, is_ptr, is_fp, is_vol, is_sig, is_vla, arr_dim, is_arr = _format_pycparser_type(node.type, self.outer.custom_typedefs)
                    shape = resolve_typedef_shape(tname, self.outer.typedef_shapes) if hasattr(self.outer, "typedef_shapes") and self.outer.typedef_shapes else None
                    v_is_array = is_arr or (shape.is_array if shape else False)
                    v_is_pointer = (is_ptr or is_fp) or (shape.is_pointer if shape else False)
                    v_arr_dim = arr_dim if arr_dim is not None else (str(shape.array_size) if shape and shape.array_size is not None else None)
                    current_block_id = self.outer.scope_stack[-1]
                    c_var = CVariable(
                        name=node.name,
                        type_name=tname,
                        is_pointer=v_is_pointer,
                        is_signed=is_sig,
                        is_volatile=is_vol,
                        is_vla=is_vla,
                        array_size_expr=v_arr_dim,
                        has_initializer=(node.init is not None),
                        declaration_line=line_no,
                        is_array=v_is_array,
                        enclosing_block_id=current_block_id,
                    )
                    var_key = (node.name, current_block_id)
                    self.outer.owning_fn.variables[var_key] = c_var

                    init_ids: Set[str] = set()
                    if node.init:
                        c_var.assigned_lines.append(line_no)
                        init_ids = _extract_read_vars_from_ast(node.init)
                        for v in init_ids:
                            target_v = self.outer.resolve_var(v)
                            if target_v:
                                target_v.read_lines.append(line_no)

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
                self.current_target_var = prev_target

            def visit_Assignment(self, node):
                prev_target = self.current_target_var
                exp_line = (node.coord.line - self.outer.prelude_offset) if node.coord else self.outer.owning_fn.start_line_exp
                line_no = _map_line(exp_line, self.outer.line_map)
                lval_ids = _extract_identifiers_from_ast(node.lvalue)
                rval_ids = _extract_read_vars_from_ast(node.rvalue)
                target = list(lval_ids)[0] if lval_ids else None
                if type(node.lvalue).__name__ == "ID":
                    target_v = self.outer.resolve_var(node.lvalue.name)
                    if target_v:
                        target_v.assigned_lines.append(line_no)
                        if node.op != '=':
                            target_v.read_lines.append(line_no)
                else:
                    lval_read_ids = _extract_read_vars_from_ast(node.lvalue)
                    for v in lval_read_ids:
                        target_v = self.outer.resolve_var(v)
                        if target_v:
                            target_v.read_lines.append(line_no)
                for v in rval_ids:
                    target_v = self.outer.resolve_var(v)
                    if target_v:
                        target_v.read_lines.append(line_no)

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
                    written_vars=lval_ids if type(node.lvalue).__name__ == "ID" else set(),
                    read_vars=rval_ids | (lval_ids if type(node.lvalue).__name__ != "ID" else set()),
                )
                self.outer.owning_fn.cfg_nodes.append(cfg_n)
                self.current_target_var = target
                self.generic_visit(node)
                self.current_target_var = prev_target

            def visit_Cast(self, node):
                exp_line = (node.coord.line - self.outer.prelude_offset) if node.coord else self.outer.owning_fn.start_line_exp
                line_no = _map_line(exp_line, self.outer.line_map)
                read_ids = _extract_read_vars_from_ast(node.expr)
                for v in read_ids:
                    target_v = self.outer.resolve_var(v)
                    if target_v:
                        target_v.read_lines.append(line_no)
                self.generic_visit(node)

            def visit_Return(self, node):
                prev_target = self.current_target_var
                self.current_target_var = "return"
                self.generic_visit(node)
                self.current_target_var = prev_target

            def visit_UnaryOp(self, node):
                exp_line = (node.coord.line - self.outer.prelude_offset) if node.coord else self.outer.owning_fn.start_line_exp
                line_no = _map_line(exp_line, self.outer.line_map)
                if node.op == '&':
                    addr_ids = _extract_read_vars_from_ast(node.expr)
                    for v in addr_ids:
                        target_v = self.outer.resolve_var(v)
                        if target_v:
                            target_v.address_taken = True
                            target_v.address_taken_lines.append(line_no)
                elif node.op in ('++', 'p++', '--', 'p--'):
                    read_ids = _extract_read_vars_from_ast(node.expr)
                    for v in read_ids:
                        target_v = self.outer.resolve_var(v)
                        if target_v:
                            target_v.read_lines.append(line_no)
                            target_v.assigned_lines.append(line_no)

                self.generic_visit(node)
                if node.op == "sizeof":
                    expr_str = _format_pycparser_expr(node.expr)
                    # We do NOT include these as read_vars because unevaluated sizeof operands
                    # are not runtime reads (avoids false-positive Use-After-Free/Uninitialized errors).
                    self.outer.node_counter += 1
                    cfg_n = CFGNode(
                        node_id=self.outer.node_counter,
                        kind="sizeof",
                        line_number=line_no,
                        expr_str=f"sizeof({expr_str})",
                        read_vars=set(),
                    )
                    self.outer.owning_fn.cfg_nodes.append(cfg_n)

                    # Ensure sizeof is treated like a call in fallback as well
                    self.outer.owning_fn.calls.append(("sizeof", line_no, expr_str, self.current_target_var))

            def visit_FuncCall(self, node):
                exp_line = (node.coord.line - self.outer.prelude_offset) if node.coord else self.outer.owning_fn.start_line_exp
                line_no = _map_line(exp_line, self.outer.line_map)
                callee = _format_pycparser_expr(node.name)
                raw_args = _format_pycparser_expr(node.args) if node.args else ""
                if callee not in ('if', 'for', 'while', 'switch', 'sizeof', 'typeof', '__attribute__'):
                    self.outer.owning_fn.calls.append((callee, line_no, raw_args, self.current_target_var))

                callee_read_ids = _extract_read_vars_from_ast(node.name)
                arg_read_ids = _extract_read_vars_from_ast(node.args) if node.args else set()
                all_read_ids = callee_read_ids | arg_read_ids
                freed_set: Set[str] = set()
                null_checked_set: Set[str] = set()

                param_names = {p.name for p in self.outer.owning_fn.parameters}
                if callee in ("free", "cfree", "vfree", "realloc"):
                    if node.args and getattr(node.args, "exprs", None):
                        freed_p = _format_pycparser_expr(node.args.exprs[0])
                        target_v = self.outer.resolve_var(freed_p)
                        if target_v:
                            target_v.freed_lines.append(line_no)
                            freed_set.add(freed_p)
                        elif freed_p in param_names:
                            freed_set.add(freed_p)

                if callee in ("assert", "ASSERT", "assert_param"):
                    self.outer.owning_fn.has_assertions = True
                    if node.args:
                        null_checked_set = _extract_read_vars_from_ast(node.args)
                        for v in null_checked_set:
                            target_v = self.outer.resolve_var(v)
                            if target_v:
                                target_v.checked_null_lines.append(line_no)

                for v in all_read_ids:
                    target_v = self.outer.resolve_var(v)
                    if target_v:
                        target_v.read_lines.append(line_no)

                self.outer.node_counter += 1
                cfg_n = CFGNode(
                    node_id=self.outer.node_counter,
                    kind="free" if freed_set else "call",
                    line_number=line_no,
                    expr_str=f"{callee}({raw_args})",
                    target_var=callee,
                    read_vars=all_read_ids,
                    freed_vars=freed_set,
                    null_checked_vars=null_checked_set,
                )
                self.outer.owning_fn.cfg_nodes.append(cfg_n)
                self.generic_visit(node)

            def visit_If(self, node):
                exp_line = (node.coord.line - self.outer.prelude_offset) if node.coord else self.outer.owning_fn.start_line_exp
                line_no = _map_line(exp_line, self.outer.line_map)
                cond_ids = _extract_read_vars_from_ast(node.cond)
                null_checked_set = set(cond_ids)
                for v in null_checked_set:
                    target_v = self.outer.resolve_var(v)
                    if target_v:
                        target_v.checked_null_lines.append(line_no)
                for v in cond_ids:
                    target_v = self.outer.resolve_var(v)
                    if target_v:
                        target_v.read_lines.append(line_no)

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
                exp_line = (node.coord.line - self.outer.prelude_offset) if node.coord else self.outer.owning_fn.start_line_exp
                line_no = _map_line(exp_line, self.outer.line_map)
                cond_ids = _extract_read_vars_from_ast(node.cond)
                null_checked_set = set(cond_ids)
                for v in null_checked_set:
                    target_v = self.outer.resolve_var(v)
                    if target_v:
                        target_v.checked_null_lines.append(line_no)
                for v in cond_ids:
                    target_v = self.outer.resolve_var(v)
                    if target_v:
                        target_v.read_lines.append(line_no)

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
                parent_id = self.outer.scope_stack[-1]
                self.outer.block_counter += 1
                block_id = self.outer.block_counter
                self.outer.block_parents[block_id] = parent_id
                self.outer.scope_stack.append(block_id)

                exp_line = (node.coord.line - self.outer.prelude_offset) if node.coord else self.outer.owning_fn.start_line_exp
                line_no = _map_line(exp_line, self.outer.line_map)
                cond_ids = _extract_read_vars_from_ast(node.cond) if node.cond else set()
                for v in cond_ids:
                    target_v = self.outer.resolve_var(v)
                    if target_v:
                        target_v.read_lines.append(line_no)

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
                self.outer.scope_stack.pop()

            def visit_Return(self, node):
                exp_line = (node.coord.line - self.outer.prelude_offset) if node.coord else self.outer.owning_fn.start_line_exp
                line_no = _map_line(exp_line, self.outer.line_map)
                ret_expr_str = _format_pycparser_expr(node.expr)
                if ret_expr_str in ("0", "1", "true", "false"):
                    if any(term in self.outer.owning_fn.name.lower() for term in ['auth', 'verify', 'check_password', 'validate_token', 'boot_secure', 'crypto', 'admin', 'login', 'permission']):
                        self.outer.owning_fn.returns_boolean = True

                ret_ids = _extract_read_vars_from_ast(node.expr) if node.expr else set()
                for v in ret_ids:
                    target_v = self.outer.resolve_var(v)
                    if target_v:
                        target_v.read_lines.append(line_no)

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
        self.owning_fn.block_parents = dict(self.block_parents)

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

    def parse(
        self,
        source_code: str,
        defined_syms: Optional[Any] = None,
        line_map: Optional[Dict[int, Any]] = None,
    ) -> CASTContext:
        lines = source_code.splitlines()
        clean_lines, clean_code = strip_comments_keep_lines(source_code)

        unsigned_typedefs: Set[str] = set()
        self._extract_unsigned_typedefs(clean_code, unsigned_typedefs)

        pycparser_res = self._try_pycparser(clean_code, defined_syms=defined_syms)
        if len(pycparser_res) == 3:
            pycparser_ast, has_pycparser, parse_tier = pycparser_res
        else:
            pycparser_ast, has_pycparser = pycparser_res
            parse_tier = ParseTier.DIRECTIVE_STRIPPED.value if has_pycparser else ParseTier.REGEX_FALLBACK.value

        clean_code = resolve_preprocessor_conditionals(clean_code, defined_syms=defined_syms)
        clean_lines = clean_code.splitlines()

        if has_pycparser and pycparser_ast is not None:
            struct_defs = self._extract_struct_defs_from_ast(pycparser_ast, clean_code)
            functions, global_vars = self._build_model_from_ast(pycparser_ast, clean_lines, clean_code, unsigned_typedefs, line_map=line_map)
            parser_status = ParserStatus.PYCPARSER_SUCCESS.value
        else:
            struct_defs = self._extract_struct_defs_from_regex(clean_code)
            functions = self._extract_functions(clean_lines, clean_code, unsigned_typedefs, line_map=line_map)
            global_vars = self._extract_global_vars(clean_lines, functions, unsigned_typedefs, line_map=line_map)
            parser_status = ParserStatus.FALLBACK_PARSER.value
            parse_tier = ParseTier.REGEX_FALLBACK.value


        typedef_shapes = getattr(self, "typedef_shapes", {})

        return CASTContext(
            functions=functions,
            global_variables=global_vars,
            source_lines=lines,
            raw_source=source_code,
            clean_source=clean_code,
            has_pycparser=has_pycparser,
            pycparser_ast=pycparser_ast,
            parser_status=parser_status,
            parse_tier=parse_tier,
            unsigned_typedefs=unsigned_typedefs,
            struct_defs=struct_defs,
            typedef_shapes=typedef_shapes,
            line_map=line_map,
        )

    def _extract_struct_defs_from_ast(self, pycparser_ast, clean_code: str) -> Dict[str, StructDef]:
        from pycparser import c_ast

        struct_defs: Dict[str, StructDef] = {}
        typedef_aliases: Dict[str, str] = {}
        typedef_shapes: Dict[str, TypedefShape] = {}

        def process_struct_or_union_node(node, name_override: Optional[str] = None):
            is_union = isinstance(node, c_ast.Union)
            struct_tag = node.name
            typedef_name = name_override
            main_name = struct_tag or typedef_name or f"anon_{id(node)}"

            fields_map: Dict[str, FieldInfo] = {}
            if getattr(node, "decls", None):
                for decl in node.decls:
                    if not getattr(decl, "name", None):
                        continue
                    f_name = decl.name
                    curr_type = decl.type

                    is_array = False
                    array_size = None
                    is_pointer = False
                    is_struct_or_union = False
                    nested_tag = None
                    is_field_union = False

                    array_dims = []
                    while isinstance(curr_type, c_ast.ArrayDecl):
                        is_array = True
                        dim_node = curr_type.dim
                        d_size = None
                        if dim_node is None:
                            d_size = None
                        elif isinstance(dim_node, c_ast.Constant):
                            try:
                                val = int(str(dim_node.value), 0)
                                d_size = val if val > 0 else None
                            except ValueError:
                                d_size = resolve_constant_expr(str(dim_node.value), clean_code)
                        elif isinstance(dim_node, c_ast.ID):
                            d_size = resolve_constant_expr(dim_node.name, clean_code)
                        else:
                            expr_str = _format_pycparser_expr(dim_node)
                            d_size = resolve_constant_expr(expr_str, clean_code)
                        array_dims.append(d_size)
                        curr_type = curr_type.type

                    if is_array:
                        array_size = array_dims[0] if array_dims else None

                    while isinstance(curr_type, c_ast.PtrDecl):
                        is_pointer = True
                        curr_type = curr_type.type

                    if isinstance(curr_type, c_ast.TypeDecl):
                        type_node = curr_type.type
                        if isinstance(type_node, c_ast.IdentifierType):
                            t_names = getattr(type_node, 'names', ['int'])
                            type_name = ' '.join(t_names)
                        elif isinstance(type_node, (c_ast.Struct, c_ast.Union)):
                            is_struct_or_union = True
                            is_field_union = isinstance(type_node, c_ast.Union)
                            nested_tag = type_node.name
                            if getattr(type_node, "decls", None):
                                nested_sd = process_struct_or_union_node(type_node)
                                nested_tag = nested_sd.name
                            type_name = f"{'union' if is_field_union else 'struct'} {nested_tag or ''}".strip()
                        else:
                            type_name = getattr(curr_type, 'declname', 'int') or 'int'
                    else:
                        type_name = _format_pycparser_expr(curr_type)

                    fields_map[f_name] = FieldInfo(
                        name=f_name,
                        type_name=type_name,
                        is_array=is_array,
                        array_size=array_size,
                        array_dims=array_dims,
                        is_pointer=is_pointer,
                        is_struct_or_union=is_struct_or_union,
                        nested_tag=nested_tag,
                        is_union=is_field_union,
                    )

            sd = StructDef(name=main_name, is_union=is_union, fields=fields_map)
            prefix = "union" if is_union else "struct"

            struct_defs[main_name] = sd
            struct_defs[f"{prefix} {main_name}"] = sd

            if struct_tag:
                struct_defs[struct_tag] = sd
                struct_defs[f"{prefix} {struct_tag}"] = sd
            if typedef_name:
                struct_defs[typedef_name] = sd
                struct_defs[f"{prefix} {typedef_name}"] = sd

            return sd

        class StructVisitor(c_ast.NodeVisitor):
            def visit_Decl(self, node):
                if isinstance(node.type, (c_ast.Struct, c_ast.Union)) and getattr(node.type, "decls", None):
                    process_struct_or_union_node(node.type)
                self.generic_visit(node)

            def visit_Typedef(self, node):
                td_name = node.name
                curr = node.type

                is_arr = False
                arr_size = None
                if isinstance(curr, c_ast.ArrayDecl):
                    is_arr = True
                    dim_node = curr.dim
                    if dim_node is None:
                        arr_size = None
                    elif isinstance(dim_node, c_ast.Constant):
                        try:
                            val = int(str(dim_node.value), 0)
                            arr_size = val if val > 0 else None
                        except ValueError:
                            arr_size = resolve_constant_expr(str(dim_node.value), clean_code)
                    elif isinstance(dim_node, c_ast.ID):
                        arr_size = resolve_constant_expr(dim_node.name, clean_code)
                    else:
                        expr_str = _format_pycparser_expr(dim_node)
                        arr_size = resolve_constant_expr(expr_str, clean_code)
                    curr = curr.type

                is_ptr = False
                while isinstance(curr, c_ast.PtrDecl):
                    is_ptr = True
                    curr = curr.type

                if isinstance(curr, c_ast.TypeDecl):
                    inner = curr.type
                    if isinstance(inner, (c_ast.Struct, c_ast.Union)):
                        underlying = inner.name or td_name
                        typedef_shapes[td_name] = TypedefShape(
                            target=underlying,
                            is_pointer=is_ptr,
                            is_array=is_arr,
                            array_size=arr_size,
                        )
                        if getattr(inner, "decls", None):
                            sd = process_struct_or_union_node(inner, name_override=td_name)
                            if sd and td_name:
                                struct_defs[td_name] = sd
                        else:
                            if inner.name:
                                typedef_aliases[td_name] = inner.name
                    elif isinstance(inner, c_ast.IdentifierType):
                        underlying = ' '.join(getattr(inner, 'names', []))
                        if underlying:
                            typedef_shapes[td_name] = TypedefShape(
                                target=underlying,
                                is_pointer=is_ptr,
                                is_array=is_arr,
                                array_size=arr_size,
                            )
                            typedef_aliases[td_name] = underlying

                self.generic_visit(node)

        StructVisitor().visit(pycparser_ast)

        self.typedef_shapes = dict(typedef_shapes)

        # Pass 2: Resolve typedef aliases and update field nested tags, pointers, and array shapes (with multi-level chain resolution)
        resolved_aliases: Set[str] = set()
        changed = True
        while changed:
            changed = False
            for alias_name, target_name in list(typedef_aliases.items()):
                if alias_name in resolved_aliases:
                    continue
                target_clean = re.sub(r'^(?:struct|union)\s+', '', target_name).strip()
                target_sd = None
                if target_name in struct_defs:
                    target_sd = struct_defs[target_name]
                elif f"struct {target_clean}" in struct_defs:
                    target_sd = struct_defs[f"struct {target_clean}"]
                elif f"union {target_clean}" in struct_defs:
                    target_sd = struct_defs[f"union {target_clean}"]
                elif target_clean in struct_defs:
                    target_sd = struct_defs[target_clean]

                if target_sd is not None:
                    struct_defs[alias_name] = target_sd
                    resolved_aliases.add(alias_name)
                    changed = True

        # Post-process fields to merge typedef pointer/array shapes and resolve nested struct/union tags
        for sd in list(struct_defs.values()):
            for field in sd.fields.values():
                raw_type = field.type_name.strip()
                clean_type = re.sub(r'^(?:const|volatile|struct|union)\s+', '', raw_type).rstrip(' *').strip()

                if clean_type in typedef_shapes:
                    shape = resolve_typedef_shape(clean_type, typedef_shapes)
                    if shape.is_pointer:
                        field.is_pointer = True
                    if shape.is_array:
                        field.is_array = True
                        if field.array_size is None:
                            field.array_size = shape.array_size

                clean_target = clean_type
                if clean_type in typedef_shapes:
                    clean_target = resolve_typedef_shape(clean_type, typedef_shapes).target
                    clean_target = re.sub(r'^(?:const|volatile|struct|union)\s+', '', clean_target).rstrip(' *').strip()

                matched_sd = None
                for candidate in (clean_target, clean_type):
                    if candidate in struct_defs:
                        matched_sd = struct_defs[candidate]
                        break
                    elif f"struct {candidate}" in struct_defs:
                        matched_sd = struct_defs[f"struct {candidate}"]
                        break
                    elif f"union {candidate}" in struct_defs:
                        matched_sd = struct_defs[f"union {candidate}"]
                        break

                if matched_sd:
                    field.is_struct_or_union = True
                    field.nested_tag = matched_sd.name
                    field.is_union = matched_sd.is_union

        return struct_defs



    def _extract_struct_defs_from_regex(self, clean_code: str) -> Dict[str, StructDef]:
        struct_defs: Dict[str, StructDef] = {}
        typedef_aliases: Dict[str, str] = {}
        typedef_shapes: Dict[str, TypedefShape] = {}

        # 1. Match typedef statements:
        # e.g. typedef struct Inner * InnerPtr_t;
        # typedef char Buffer16_t[16];
        # typedef struct A A_t;
        typedef_stmt_regex = re.compile(
            r'\btypedef\s+([^;]+);',
            re.MULTILINE
        )
        for m in typedef_stmt_regex.finditer(clean_code):
            body = m.group(1).strip()
            if '{' in body or '}' in body:
                continue
            m_arr = re.search(r'^(.*?)\b([a-zA-Z_]\w*)\s*\[\s*([^\]]*)\s*\]$', body)
            m_decl = re.search(r'^(.*?)\b([a-zA-Z_]\w*)$', body)
            if m_arr:
                base_t = m_arr.group(1).strip()
                td_name = m_arr.group(2).strip()
                dim_s = m_arr.group(3).strip()
                is_ptr = '*' in base_t
                arr_sz = resolve_constant_expr(dim_s, clean_code) if dim_s else None
                clean_target = re.sub(r'^(?:const|volatile|struct|union)\s+', '', base_t).rstrip(' *').strip()
                typedef_shapes[td_name] = TypedefShape(
                    target=clean_target,
                    is_pointer=is_ptr,
                    is_array=True,
                    array_size=arr_sz,
                )
                typedef_aliases[td_name] = clean_target
            elif m_decl:
                base_t = m_decl.group(1).strip()
                td_name = m_decl.group(2).strip()
                is_ptr = '*' in base_t or '*' in td_name
                clean_target = re.sub(r'^(?:const|volatile|struct|union)\s+', '', base_t).rstrip(' *').strip()
                typedef_shapes[td_name] = TypedefShape(
                    target=clean_target,
                    is_pointer=is_ptr,
                    is_array=False,
                    array_size=None,
                )
                typedef_aliases[td_name] = clean_target

        # 2. Find struct and union definitions with bodies: [typedef] struct/union [Tag] { body } [Aliases];
        struct_def_regex = re.compile(
            r'\b(typedef\s+)?(struct|union)\b\s*([a-zA-Z_]\w*)?\s*\{',
            re.MULTILINE
        )

        n = len(clean_code)
        for m in struct_def_regex.finditer(clean_code):
            is_typedef = bool(m.group(1))
            kw = m.group(2)
            is_union = (kw == 'union')
            tag = m.group(3)

            body_start = m.end()
            brace_count = 1
            curr_pos = body_start
            while curr_pos < n and brace_count > 0:
                ch = clean_code[curr_pos]
                if ch == '{':
                    brace_count += 1
                elif ch == '}':
                    brace_count -= 1
                curr_pos += 1

            if brace_count != 0:
                continue

            body = clean_code[body_start:curr_pos - 1]

            after_pos = curr_pos
            semicolon_pos = clean_code.find(';', after_pos)
            trailing_str = ""
            if semicolon_pos != -1 and semicolon_pos - after_pos < 100:
                trailing_str = clean_code[after_pos:semicolon_pos].strip()

            aliases = []
            if trailing_str:
                for token in trailing_str.split(','):
                    t = token.strip().lstrip('*').strip()
                    if t and t.isidentifier():
                        aliases.append(t)

            fields_map: Dict[str, FieldInfo] = {}

            member_stmts = split_c_statements_at_outer_depth(body)
            for stmt in member_stmts:
                parsed_fields = parse_member_declarations(stmt, clean_code)
                for f in parsed_fields:
                    fields_map[f.name] = f

            main_name = tag or (aliases[0] if aliases else f"anon_{m.start()}")
            sd = StructDef(name=main_name, is_union=is_union, fields=fields_map)
            prefix = "union" if is_union else "struct"

            if tag:
                struct_defs[tag] = sd
                struct_defs[f"{prefix} {tag}"] = sd

            for alias in aliases:
                struct_defs[alias] = sd
                struct_defs[f"{prefix} {alias}"] = sd

        self.typedef_shapes = dict(typedef_shapes)

        # Pass 2: Resolve simple typedef aliases (with multi-level chain resolution)
        resolved_aliases: Set[str] = set()
        changed = True
        while changed:
            changed = False
            for alias_name, target_name in list(typedef_aliases.items()):
                if alias_name in resolved_aliases:
                    continue
                target_clean = re.sub(r'^(?:struct|union)\s+', '', target_name).strip()
                target_sd = None
                if target_name in struct_defs:
                    target_sd = struct_defs[target_name]
                elif f"struct {target_clean}" in struct_defs:
                    target_sd = struct_defs[f"struct {target_clean}"]
                elif f"union {target_clean}" in struct_defs:
                    target_sd = struct_defs[f"union {target_clean}"]
                elif target_clean in struct_defs:
                    target_sd = struct_defs[target_clean]

                if target_sd is not None:
                    struct_defs[alias_name] = target_sd
                    resolved_aliases.add(alias_name)
                    changed = True

        # Post-process fields for nested structs/unions and typedef shapes
        for sd in list(struct_defs.values()):
            for field in sd.fields.values():
                raw_type = field.type_name.strip()
                clean_type = re.sub(r'^(?:const|volatile|struct|union)\s+', '', raw_type).rstrip(' *').strip()
                if field.name and clean_type.endswith(field.name):
                    clean_type = clean_type[:-len(field.name)].strip()
                clean_type = clean_type.rstrip(' *').strip()

                if clean_type in typedef_shapes:
                    shape = resolve_typedef_shape(clean_type, typedef_shapes)
                    if shape.is_pointer:
                        field.is_pointer = True
                    if shape.is_array:
                        field.is_array = True
                        if field.array_size is None:
                            field.array_size = shape.array_size

                clean_target = clean_type
                if clean_type in typedef_shapes:
                    clean_target = resolve_typedef_shape(clean_type, typedef_shapes).target
                    clean_target = re.sub(r'^(?:const|volatile|struct|union)\s+', '', clean_target).rstrip(' *').strip()

                matched_sd = None
                for candidate in (clean_target, clean_type):
                    if candidate in struct_defs:
                        matched_sd = struct_defs[candidate]
                        break
                    elif f"struct {candidate}" in struct_defs:
                        matched_sd = struct_defs[f"struct {candidate}"]
                        break
                    elif f"union {candidate}" in struct_defs:
                        matched_sd = struct_defs[f"union {candidate}"]
                        break

                if matched_sd:
                    field.is_struct_or_union = True
                    field.nested_tag = matched_sd.name
                    field.is_union = matched_sd.is_union

        return struct_defs

    def _extract_unsigned_typedefs(self, clean_code: str, target_set: Set[str]) -> None:
        """
        Extracts custom unsigned typedef names from comment-stripped source code,
        supporting single and multi-declarator typedef statements as well as pointer declarators.
        """
        typedef_stmt_regex = re.compile(r'\btypedef\s+([^;]+);', re.MULTILINE)
        for match in typedef_stmt_regex.finditer(clean_code):
            stmt_body = match.group(1).strip()
            if not stmt_body:
                continue

            # Split on top-level commas (ignoring commas inside nested parentheses/brackets)
            tokens: List[str] = []
            current = []
            paren_depth = 0
            bracket_depth = 0
            for char in stmt_body:
                if char == '(':
                    paren_depth += 1
                elif char == ')':
                    paren_depth = max(0, paren_depth - 1)
                elif char == '[':
                    bracket_depth += 1
                elif char == ']':
                    bracket_depth = max(0, bracket_depth - 1)

                if char == ',' and paren_depth == 0 and bracket_depth == 0:
                    tokens.append(''.join(current).strip())
                    current = []
                else:
                    current.append(char)
            if current:
                tokens.append(''.join(current).strip())

            if not tokens:
                continue

            # First token contains the base type and the first declarator
            first_part = tokens[0]
            # Match base type and declarator identifier
            # e.g. "unsigned int u32", "unsigned int *pu32", "uint8_t (*func_ptr)(int)"
            m_fn_ptr = re.search(r'^(.*?)\(\s*\*\s*([a-zA-Z_]\w*)\s*\)\s*\(.*?\)$', first_part)
            if m_fn_ptr:
                base_type = m_fn_ptr.group(1).strip()
                alias = m_fn_ptr.group(2).strip()
                if is_unsigned_type(base_type, target_set):
                    target_set.add(alias)
            else:
                m_decl = re.search(r'^(.*?)\b([a-zA-Z_]\w*)\s*(?:\[[^\]]*\])?$', first_part)
                if m_decl:
                    base_type = m_decl.group(1).strip()
                    first_alias = m_decl.group(2).strip()
                    if is_unsigned_type(base_type, target_set):
                        target_set.add(first_alias)

                        # Subsequent tokens in multi-declarator typedef share the same base_type
                        for sub_tok in tokens[1:]:
                            m_sub_fn = re.search(r'\(\s*\*\s*([a-zA-Z_]\w*)\s*\)', sub_tok)
                            if m_sub_fn:
                                target_set.add(m_sub_fn.group(1).strip())
                            else:
                                m_sub = re.search(r'\b([a-zA-Z_]\w*)\s*(?:\[[^\]]*\])?$', sub_tok)
                                if m_sub:
                                    target_set.add(m_sub.group(1).strip())

    @staticmethod
    def strip_only(source_code: str) -> Tuple[List[str], str]:
        """
        Cheap path used by the engine in REGEX-only mode: just returns
        comment-stripped lines/code without the (much more expensive)
        function/variable extraction or pycparser attempt.
        """
        return strip_comments_keep_lines(source_code)

    def _try_pycparser(self, clean_code: str, defined_syms: Optional[Any] = None):
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
            return None, False, ParseTier.REGEX_FALLBACK.value

        # Tier 1: pcpp preprocessing (if available)
        pcpp_result = self._try_pcpp_preprocess(clean_code, defined_syms=defined_syms)
        if pcpp_result is not None:
            try:
                parser = c_parser.CParser()
                pycparser_ast = parser.parse(pcpp_result, filename='<input>')
                return pycparser_ast, True, ParseTier.PCPP_PYCPARSER.value
            except Exception:
                pass  # Fall through to tier 2

        # Tier 2: Conditional resolution + Directive stripping + typedef prelude
        resolved_code = resolve_preprocessor_conditionals(clean_code, defined_syms=defined_syms)
        directive_stripped_lines = [
            "" if line.lstrip().startswith("#") else line
            for line in resolved_code.splitlines()
        ]
        directive_stripped_code = "\n".join(directive_stripped_lines)
        if resolved_code.endswith("\n") and not directive_stripped_code.endswith("\n"):
            directive_stripped_code += "\n"
        stripped_code = _strip_attributes_and_specifiers(directive_stripped_code)
        filtered_prelude = self._filter_prelude(_PYCPARSER_PRELUDE, stripped_code)
        prepared = filtered_prelude + stripped_code

        try:
            parser = c_parser.CParser()
            pycparser_ast = parser.parse(prepared, filename='<input>')
            return pycparser_ast, True, ParseTier.DIRECTIVE_STRIPPED.value
        except Exception:
            return None, False, ParseTier.REGEX_FALLBACK.value

    def _filter_prelude(self, prelude_text: str, code_text: str) -> str:
        """Filters out typedefs from the prelude that are explicitly re-declared in code_text."""
        filtered = []
        for line in prelude_text.splitlines(keepends=True):
            line_s = line.strip()
            if line_s.startswith('typedef '):
                parts = line_s.rstrip(';\n').split()
                if len(parts) >= 3:
                    name = parts[-1]
                    if re.search(r'\btypedef\s+[^;]*\b' + re.escape(name) + r'\b\s*;', code_text):
                        filtered.append('\n' if line.endswith('\n') else '')
                        continue
            filtered.append(line)
        return ''.join(filtered)

    def _try_pcpp_preprocess(self, clean_code: str, defined_syms: Optional[Any] = None) -> "Optional[str]":
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
            """Suppresses errors, passes through unresolvable #includes, and syncs #line directives on drift."""
            def __init__(self, *args, **kwargs):
                super().__init__(*args, **kwargs)
                self.line_directive = '#line'

            def on_error(self, file, line, msg):
                pass

            def on_include_not_found(self, is_malformed, is_system_include,
                                     curdir, includepath):
                raise pcpp.OutputDirective(pcpp.Action.IgnoreAndPassThrough)

            def write(self, oh=None):
                """Custom write loop based on pcpp.Preprocessor.write (pcpp v1.30) that forces

                emitting a #line directive whenever lineno drifts (e.g. multi-line macro calls).
                """
                if oh is None:
                    import sys
                    oh = sys.stdout
                lastlineno = 0
                lastsource = None
                done = False
                blanklines = 0
                while not done:
                    emitlinedirective = False
                    toks = []
                    all_ws = True
                    while not done:
                        tok = self.token()
                        if not tok:
                            done = True
                            break
                        toks.append(tok)
                        if tok.value and tok.value[0] == '\n':
                            break
                        if tok.type not in self.t_WS:
                            all_ws = False
                    if not toks:
                        break
                    if all_ws:
                        if len(toks) > 1:
                            tok = toks[-1]
                            toks = [tok]
                        blanklines += toks[0].value.count('\n')
                        continue
                    for n in range(len(toks) - 1, -1, -1):
                        if self.t_LINECONT is not None and toks[n].type == self.t_LINECONT:
                            if n > 0 and n < len(toks) - 2 and toks[n - 1].type in self.t_WS and toks[n + 1].type in self.t_WS:
                                if self.t_LINECONT is None or toks[n - 1].type != self.t_LINECONT:
                                    toks[n - 1].value = toks[n - 1].value[0]
                                    del toks[n:n + 2]
                            else:
                                del toks[n]
                    emitlinedirective = (blanklines > 6) and self.line_directive is not None
                    if hasattr(toks[0], 'source'):
                        if lastsource is None:
                            if toks[0].source is not None:
                                emitlinedirective = True
                            lastsource = toks[0].source
                        elif lastsource != toks[0].source:
                            emitlinedirective = True
                            lastsource = toks[0].source
                    first_ws = None
                    for n in range(len(toks) - 1, -1, -1):
                        tok = toks[n]
                        if first_ws is None:
                            if (self.t_SPACE is not None and tok.type == self.t_SPACE) or len(tok.value) == 0:
                                first_ws = n
                        else:
                            if (self.t_SPACE is None or tok.type != self.t_SPACE) and len(tok.value) > 0:
                                m = n + 1
                                while m != first_ws:
                                    del toks[m]
                                    first_ws -= 1
                                first_ws = None
                                if self.compress > 0:
                                    if toks[m].value and toks[m].value[0] == ' ':
                                        toks[m].value = ' '
                    if toks[0].lineno != lastlineno + 1:
                        emitlinedirective = True
                    lastlineno = toks[0].lineno
                    if emitlinedirective and self.line_directive is not None:
                        oh.write(self.line_directive + ' ' + str(lastlineno) + ('' if lastsource is None else (' "' + lastsource + '"')) + '\n')
                    for tok in toks:
                        if tok.type == self.t_COMMENT1:
                            lastlineno += tok.value.count('\n')
                    blanklines = 0
                    for tok in toks:
                        oh.write(tok.value)

        try:
            preprocessor = _SilentPreprocessor()
            if defined_syms:
                if isinstance(defined_syms, (set, list, tuple, frozenset)):
                    for s in defined_syms:
                        item = str(s).strip()
                        if " " in item:
                            preprocessor.define(item)
                        else:
                            preprocessor.define(f"{item} 1")
                elif isinstance(defined_syms, (dict, Mapping)):
                    for k, v in defined_syms.items():
                        key = str(k)
                        if v is False:
                            preprocessor.undef(key)
                    norm_macros = _normalize_macro_dict(defined_syms)
                    for k, v in norm_macros.items():
                        preprocessor.define(f"{k} {v}")
                else:
                    norm_macros = _normalize_macro_dict(defined_syms)
                    for k, v in norm_macros.items():
                        preprocessor.define(f"{k} {v}")

            # Feed the typedef prelude + source as a single unit so that
            # macros defined in the source are expanded while the prelude
            # typedefs are preserved for pycparser.
            filtered_prelude = self._filter_prelude(_PYCPARSER_PRELUDE, clean_code)
            combined = filtered_prelude + clean_code
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
        self, pycparser_ast, clean_lines: List[str], clean_code: str, custom_typedefs: Optional[Set[str]] = None, line_map: Optional[Dict[int, Any]] = None
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
            if isinstance(ext, c_ast.Typedef) and custom_typedefs is not None:
                tname, _, _, _, is_sig, _, _, _ = _format_pycparser_type(ext.type, custom_typedefs)
                if not is_sig and ext.name:
                    custom_typedefs.add(ext.name)
            elif isinstance(ext, c_ast.Decl) and type(ext.type).__name__ != "FuncDecl" and type(ext).__name__ != "Typedef":
                exp_line = (ext.coord.line - _PRELUDE_LINE_COUNT) if ext.coord else 1
                line_no = _map_line(exp_line, line_map)
                tname, is_ptr, is_fp, is_vol, is_sig, is_vla, arr_dim, is_arr = _format_pycparser_type(ext.type, custom_typedefs)
                shape = resolve_typedef_shape(tname, self.typedef_shapes) if hasattr(self, "typedef_shapes") and self.typedef_shapes else None
                v_is_array = is_arr or (shape.is_array if shape else False)
                v_is_pointer = (is_ptr or is_fp) or (shape.is_pointer if shape else False)
                v_arr_dim = arr_dim if arr_dim is not None else (str(shape.array_size) if shape and shape.array_size is not None else None)
                if ext.name and ext.name not in ('typedef', '#include', '#define', '#ifdef', '#ifndef'):
                    global_vars[ext.name] = CVariable(
                        name=ext.name,
                        type_name=tname,
                        is_pointer=v_is_pointer,
                        is_signed=is_sig,
                        is_volatile=is_vol,
                        is_vla=is_vla,
                        array_size_expr=v_arr_dim,
                        has_initializer=(ext.init is not None),
                        declaration_line=line_no,
                        is_array=v_is_array,
                    )

            elif isinstance(ext, c_ast.FuncDef):
                fname = ext.decl.name
                fn_start_exp = (ext.decl.coord.line - _PRELUDE_LINE_COUNT) if ext.decl.coord else 1
                fn_start = _map_line(fn_start_exp, line_map)

                ret_t, _, _, _, _, _, _, _ = _format_pycparser_type(ext.decl.type.type, custom_typedefs)

                params: List[CParameter] = []
                has_void_param = False
                is_empty_params = False
                func_args = ext.decl.type.args

                if func_args is None or not getattr(func_args, "params", None):
                    is_empty_params = True
                else:
                    if len(func_args.params) == 1:
                        p0 = func_args.params[0]
                        if hasattr(p0, "type"):
                            p0_type, _, _, _, _, _, _, _ = _format_pycparser_type(p0.type, custom_typedefs)
                            if p0_type == "void" and (not getattr(p0, "name", None) or p0.name == "void"):
                                has_void_param = True

                    if not has_void_param:
                        for param in func_args.params:
                            if type(param).__name__ == "EllipsisParam" or not hasattr(param, "type"):
                                continue
                            p_name = getattr(param, "name", None) or ""
                            p_type, p_is_ptr, p_is_fp, _, _, _, _, p_is_arr = _format_pycparser_type(param.type, custom_typedefs)
                            p_line_exp = (param.coord.line - _PRELUDE_LINE_COUNT) if param.coord else fn_start_exp
                            p_line = _map_line(p_line_exp, line_map)
                            p_shape = resolve_typedef_shape(p_type, self.typedef_shapes) if hasattr(self, "typedef_shapes") and self.typedef_shapes else None
                            p_is_array = p_is_arr or (p_shape.is_array if p_shape else False)
                            p_is_pointer = p_is_ptr or p_is_fp or (p_shape.is_pointer if p_shape else False)
                            params.append(CParameter(
                                name=p_name,
                                type_name=p_type,
                                is_pointer=p_is_pointer,
                                line_number=p_line,
                                is_array=p_is_array,
                            ))

                fn_end_exp = _get_max_ast_line(ext.body, fn_start_exp, _PRELUDE_LINE_COUNT)
                brace_count = 0
                for l in range(fn_start_exp, len(clean_lines) + 1):
                    line_str = clean_lines[l - 1]
                    brace_count += line_str.count("{") - line_str.count("}")
                    if l >= fn_end_exp and brace_count <= 0:
                        fn_end_exp = l
                        break

                fn_end = _map_line(fn_end_exp, line_map)
                fn_body = "\n".join(clean_lines[fn_start_exp: max(fn_start_exp, fn_end_exp - 1)]) if fn_start_exp < fn_end_exp else ""
                body_start_line = _map_line(fn_start_exp + 1 if fn_start_exp < fn_end_exp else fn_start_exp, line_map)

                fn = CFunction(
                    name=fname,
                    return_type=ret_t,
                    parameters=params,
                    start_line=fn_start,
                    end_line=fn_end,
                    body=fn_body,
                    has_void_param_list=has_void_param,
                    is_empty_param_list=is_empty_params,
                    body_start_line=body_start_line,
                    start_line_exp=fn_start_exp,
                    end_line_exp=fn_end_exp,
                )

                if ext.body:
                    _ASTFunctionAnalyzer(fn, _PRELUDE_LINE_COUNT, clean_lines, custom_typedefs, typedef_shapes=self.typedef_shapes, line_map=line_map).analyze(ext.body)

                functions.append(fn)

        return functions, global_vars

    def _extract_functions(self, lines: List[str], full_code: str, custom_typedefs: Optional[Set[str]] = None, line_map: Optional[Dict[int, Any]] = None) -> List[CFunction]:
        functions: List[CFunction] = []
        # Pattern to match C function header: return_type func_name(params) {
        # e.g., int auth_user(char *user, const char *pass)
        func_header_regex = re.compile(
            r'^[ \t]*((?:(?:static|inline|extern|const|unsigned|signed|struct\s+\w+|\w+)\s+)+)(\*?\s*[\w_]+)\s*\(([^)]*)\)\s*\{',
            re.MULTILINE
        )

        for match in func_header_regex.finditer(full_code):
            start_pos = match.start()
            start_line_exp = full_code[:start_pos].count('\n') + 1
            start_line = _map_line(start_line_exp, line_map)

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

            end_line_exp = full_code[:curr_pos].count('\n') + 1
            end_line = _map_line(end_line_exp, line_map)
            body = full_code[body_start_pos:curr_pos - 1]
            body_start_line_exp = full_code[:body_start_pos].count('\n') + 1
            body_start_line = _map_line(body_start_line_exp, line_map)

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

                    p_is_arr = False
                    m_p_arr = re.match(r'^([a-zA-Z_]\w*)\s*(\[[^\]]*\])$', p_name)
                    if m_p_arr:
                        p_name = m_p_arr.group(1)
                        p_type = f"{p_type}{m_p_arr.group(2)}"
                        p_is_arr = True

                    if '[' in p_type:
                        p_is_arr = True

                    params.append(CParameter(name=p_name, type_name=p_type, is_pointer=is_ptr, line_number=start_line, is_array=p_is_arr))

            fn = CFunction(
                name=func_name,
                return_type=ret_type,
                parameters=params,
                start_line=start_line,
                end_line=end_line,
                body=body,
                has_void_param_list=has_void_param,
                is_empty_param_list=is_empty_params,
                body_start_line=body_start_line,
                start_line_exp=start_line_exp,
                end_line_exp=end_line_exp,
            )

            # Analyze function body variables & calls
            self._analyze_function_body(fn, lines, custom_typedefs, line_map=line_map)
            functions.append(fn)

        return functions

    def _analyze_function_body(self, fn: CFunction, all_lines: List[str], custom_typedefs: Optional[Set[str]] = None, line_map: Optional[Dict[int, Any]] = None) -> None:
        body_lines = fn.body.splitlines()
        fn_start_exp = fn.start_line_exp or fn.start_line

        # Detect assertions
        if "assert(" in fn.body or "ASSERT(" in fn.body or "assert_param(" in fn.body:
            fn.has_assertions = True

        # Detect boolean return in security context
        if re.search(r'\breturn\s+(?:0|1|true|false)\s*;', fn.body):
            if any(term in fn.name.lower() for term in ['auth', 'verify', 'check_password', 'validate_token', 'boot_secure', 'crypto', 'admin', 'login', 'permission']):
                fn.returns_boolean = True

        # Extract function calls inside body
        # We parse the full body string to handle multiline arguments and nested parentheses
        call_regex = re.compile(r'\b([a-zA-Z_]\w*)\s*\(')
        for m in call_regex.finditer(fn.body):
            callee = m.group(1)
            if callee not in ('if', 'for', 'while', 'switch', 'sizeof', 'typeof', '__attribute__'):
                # Match balanced parens to get args
                args_start = m.end() - 1
                paren_depth = 0
                in_string = False
                in_char = False
                escape = False
                j = args_start
                n = len(fn.body)
                while j < n:
                    c = fn.body[j]
                    if escape:
                        escape = False
                    elif c == '\\':
                        escape = True
                    elif c == '"' and not in_char:
                        in_string = not in_string
                    elif c == "'" and not in_string:
                        in_char = not in_char
                    elif not in_string and not in_char:
                        if c == '(':
                            paren_depth += 1
                        elif c == ')':
                            paren_depth -= 1
                            if paren_depth == 0:
                                break
                    j += 1

                if j < n:
                    args = fn.body[args_start + 1 : j]
                    # Calc line number
                    prefix = fn.body[:m.start()]
                    exp_line = fn_start_exp + prefix.count('\n')
                    line_no = _map_line(exp_line, line_map)

                    target_var = None
                    stmt_prefix_match = re.search(r'(?:^|[;{}])\s*([^;{}]+)\s*=\s*[^;{}]*$', prefix)
                    if stmt_prefix_match:
                        m_var = re.search(r'\b([a-zA-Z_]\w*)\s*(?:\[[^\]]*\])?$', stmt_prefix_match.group(1))
                        if m_var:
                            target_var = m_var.group(1)

                    fn.calls.append((callee, line_no, args, target_var))

        C_KEYWORDS = {
            'return', 'break', 'continue', 'goto', 'case', 'default', 'if', 'else', 'for', 'while',
            'switch', 'sizeof', 'typeof', 'typedef', 'struct', 'union', 'enum', 'extern', 'static',
            'const', 'volatile', 'register', 'inline', 'restrict', '0', '1', 'NULL'
        }

        # Track local variable declarations and block scope hierarchy
        var_decl_regex = re.compile(
            r'^[ \t]*((?:volatile\s+|static\s+|const\s+|unsigned\s+|signed\s+|struct\s+\w+|\w+)\s+(?:\*|\w|\s)*?)\s*([a-zA-Z_]\w*)(?:\[([^\]]*)\])?(?:\s*=\s*([^;]+))?;'
        )
        ptr_arr_decl_regex = re.compile(
            r'^[ \t]*((?:volatile\s+|static\s+|const\s+|unsigned\s+|signed\s+|struct\s+\w+|\w+)\s+)\(\s*\*\s*([a-zA-Z_]\w*)\s*\)(?:\[([^\]]*)\])?(?:\s*=\s*([^;]+))?;'
        )
        block_counter = 0
        scope_stack = [0]
        block_parents = {}

        for i, line in enumerate(body_lines):
            exp_line = fn_start_exp + i
            line_no = _map_line(exp_line, line_map)
            masked_line = mask_string_and_char_literals(line)
            m = var_decl_regex.match(line)
            m_parr = ptr_arr_decl_regex.match(line) if not m else None
            m_target = m or m_parr
            decl_start = m_target.start() if m_target else len(line)

            for pos, char in enumerate(masked_line):
                if pos == decl_start and m_target:
                    type_prefix = m_target.group(1).strip()
                    v_name = m_target.group(2).strip()
                    array_dim = m_target.group(3)
                    init_val = m_target.group(4)

                    if v_name not in C_KEYWORDS and v_name.isidentifier():
                        type_tokens = type_prefix.split()
                        if not (type_tokens and type_tokens[-1] in _STATEMENT_KEYWORDS):
                            is_ptr = '*' in type_prefix or '*' in v_name or (m_parr is not None)
                            is_signed = not is_unsigned_type(type_prefix, custom_typedefs)
                            is_volatile = 'volatile' in type_prefix
                            is_vla = False
                            if array_dim is not None:
                                dim_clean = array_dim.strip()
                                if dim_clean and not dim_clean.isdigit() and not dim_clean.isupper() and not dim_clean.startswith('0x'):
                                    is_vla = True

                            curr_block = scope_stack[-1]
                            shape = resolve_typedef_shape(type_prefix, self.typedef_shapes) if hasattr(self, "typedef_shapes") and self.typedef_shapes else None
                            v_is_array = (array_dim is not None) or (shape.is_array if shape else False)
                            v_is_pointer = is_ptr or (shape.is_pointer if shape else False)
                            v_arr_dim = array_dim if array_dim is not None else (str(shape.array_size) if shape and shape.array_size is not None else None)
                            c_var = CVariable(
                                name=v_name,
                                type_name=type_prefix,
                                is_pointer=v_is_pointer,
                                is_signed=is_signed,
                                is_volatile=is_volatile,
                                is_vla=is_vla,
                                array_size_expr=v_arr_dim,
                                has_initializer=(init_val is not None),
                                declaration_line=line_no,
                                is_array=v_is_array,
                                enclosing_block_id=curr_block,
                            )
                            if init_val:
                                c_var.assigned_lines.append(line_no)
                            fn.variables[(v_name, curr_block)] = c_var

                if char == '{':
                    block_counter += 1
                    parent_id = scope_stack[-1]
                    block_parents[block_counter] = parent_id
                    scope_stack.append(block_counter)
                elif char == '}':
                    if len(scope_stack) > 1:
                        scope_stack.pop()

        fn.block_parents = block_parents

        # Track variable life cycles (free, null-checks, reads, assignments, address-taking)
        assign_regex = re.compile(r'^\s*([a-zA-Z_]\w*)\s*(?:\[[^\]]*\]|\.\w+|->\w+)*\s*=(?!=)')
        for i, line in enumerate(body_lines):
            exp_line = fn_start_exp + i
            line_no = _map_line(exp_line, line_map)
            m_assign = assign_regex.match(line)
            if m_assign:
                v_name = m_assign.group(1)
                if v_name in fn.variables:
                    if line_no not in fn.variables[v_name].assigned_lines:
                        fn.variables[v_name].assigned_lines.append(line_no)

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

            # Check address-taking & reads for local variables in fallback mode
            for v_name, c_var in fn.variables.items():
                if not v_name or v_name in C_KEYWORDS:
                    continue

                # Address-taken check: &v_name
                if re.search(rf'&\s*\b{re.escape(v_name)}\b', line):
                    c_var.address_taken = True
                    if line_no not in c_var.address_taken_lines:
                        c_var.address_taken_lines.append(line_no)

                # Read check:
                if re.search(rf'\b{re.escape(v_name)}\b', line):
                    is_read = False
                    # 1. Declaration line: read if v_name appears in initializer / RHS or multiple times on decl line
                    if line_no == c_var.declaration_line:
                        if '=' in line:
                            rhs = line.split('=', 1)[1]
                            if re.search(rf'\b{re.escape(v_name)}\b', rhs):
                                is_read = True
                        # Check if v_name appears > 1 times on declaration line
                        if len(re.findall(rf'\b{re.escape(v_name)}\b', line)) > 1:
                            is_read = True
                    else:
                        # 2. Compound assignment / inc / dec on v_name
                        if re.search(rf'\b{re.escape(v_name)}\s*(?:\+\+|--|\+=|-=|\*=|/=|%=|&=|\|=|\^=|<<=|>>=)', line) or \
                           re.search(rf'(?:\+\+|--)\s*\b{re.escape(v_name)}\b', line):
                            is_read = True
                        else:
                            # 3. Pure LHS assignment v_name = ...
                            m_pure_assign = re.match(rf'^\s*{re.escape(v_name)}\s*=(?!=)\s*(.*)$', line)
                            if m_pure_assign:
                                rhs = m_pure_assign.group(1)
                                if re.search(rf'\b{re.escape(v_name)}\b', rhs):
                                    is_read = True
                            else:
                                is_read = True

                    if is_read and line_no not in c_var.read_lines:
                        c_var.read_lines.append(line_no)

    def _extract_global_vars(self, lines: List[str], functions: List[CFunction], custom_typedefs: Optional[Set[str]] = None, line_map: Optional[Dict[int, Any]] = None) -> Dict[str, CVariable]:
        global_vars: Dict[str, CVariable] = {}
        func_line_ranges = set()
        for fn in functions:
            start_exp = fn.start_line_exp or fn.start_line
            end_exp = fn.end_line_exp or fn.end_line
            for l in range(start_exp, end_exp + 1):
                func_line_ranges.add(l)

        var_decl_regex = re.compile(
            r'^[ \t]*((?:volatile\s+|static\s+|const\s+|unsigned\s+|signed\s+|struct\s+\w+|\w+)\s+(?:\*|\w|\s)*?)\s*(\w+)(?:\[([^\]]*)\])?(?:\s*=\s*([^;]+))?;'
        )

        for line_no_exp, line in enumerate(lines, 1):
            if line_no_exp in func_line_ranges:
                continue
            line_no = _map_line(line_no_exp, line_map)
            m = var_decl_regex.match(line)
            if m:
                type_prefix = m.group(1).strip()
                v_name = m.group(2).strip()
                type_tokens = type_prefix.split()
                if type_tokens and type_tokens[-1] in _STATEMENT_KEYWORDS:
                    continue
                if v_name not in ('typedef', '#include', '#define', '#ifdef', '#ifndef'):
                    shape = resolve_typedef_shape(type_prefix, self.typedef_shapes) if hasattr(self, "typedef_shapes") and self.typedef_shapes else None
                    v_is_array = (m.group(3) is not None) or (shape.is_array if shape else False)
                    v_is_pointer = ('*' in type_prefix) or (shape.is_pointer if shape else False)
                    v_arr_dim = m.group(3) if m.group(3) is not None else (str(shape.array_size) if shape and shape.array_size is not None else None)
                    global_vars[v_name] = CVariable(
                        name=v_name,
                        type_name=type_prefix,
                        is_pointer=v_is_pointer,
                        is_signed=not is_unsigned_type(type_prefix, custom_typedefs),
                        is_volatile='volatile' in type_prefix,
                        is_vla=False,
                        array_size_expr=v_arr_dim,
                        has_initializer=m.group(4) is not None,
                        declaration_line=line_no,
                        is_array=v_is_array,
                    )
        return global_vars


# Alias for backward compatibility
ASTAnalyzer = CASTParser
