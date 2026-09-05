"""Performance-focused overrides for C AST fallback extraction.

The legacy extractor remains in :mod:`cgull.ast_analyzer.visitor` for
backward compatibility.  This module provides the public parser class with
line-number and function-range bookkeeping that stays linear (or n log n)
on files containing thousands of small functions.
"""

from bisect import bisect_left
import re
from typing import Any, Dict, List, Optional, Set

from .configuration import _STATEMENT_KEYWORDS, is_unsigned_type
from .types import CFunction, CParameter, CVariable, _map_line, resolve_typedef_shape
from .visitor import CASTParser as _LegacyCASTParser


class CASTParser(_LegacyCASTParser):
    """CAST parser with optimized regex-fallback extraction bookkeeping."""

    def _extract_functions(
        self,
        lines: List[str],
        full_code: str,
        custom_typedefs: Optional[Set[str]] = None,
        line_map: Optional[Dict[int, Any]] = None,
    ) -> List[CFunction]:
        functions: List[CFunction] = []
        func_header_regex = re.compile(
            r'^[ \t]*((?:(?:static|inline|extern|const|unsigned|signed|struct\s+\w+|\w+)\s+)+)(\*?\s*[\w_]+)\s*\(([^)]*)\)\s*\{',
            re.MULTILINE,
        )

        # Legacy extraction repeatedly sliced the entire prefix and counted
        # newlines for every function boundary.  On N tiny functions that is
        # O(N^2) in total source size.  Index newlines once and use binary
        # search for exact legacy-compatible line numbers instead.
        newline_offsets = [i for i, ch in enumerate(full_code) if ch == "\n"]

        def line_at(pos: int) -> int:
            return bisect_left(newline_offsets, pos) + 1

        for match in func_header_regex.finditer(full_code):
            start_pos = match.start()
            start_line_exp = line_at(start_pos)
            start_line = _map_line(start_line_exp, line_map)

            ret_type = match.group(1).strip()
            raw_name = match.group(2).strip()
            params_str = match.group(3).strip()

            if raw_name.startswith("*"):
                ret_type += " *"
                func_name = raw_name[1:].strip()
            else:
                func_name = raw_name

            if func_name in ("if", "for", "while", "switch", "catch"):
                continue

            brace_count = 1
            body_start_pos = match.end()
            curr_pos = body_start_pos
            n = len(full_code)
            while curr_pos < n and brace_count > 0:
                ch = full_code[curr_pos]
                if ch == "{":
                    brace_count += 1
                elif ch == "}":
                    brace_count -= 1
                curr_pos += 1

            end_line_exp = line_at(curr_pos)
            end_line = _map_line(end_line_exp, line_map)
            body = full_code[body_start_pos : curr_pos - 1]
            body_start_line = _map_line(line_at(body_start_pos), line_map)

            params: List[CParameter] = []
            is_empty_params = params_str == ""
            has_void_param = params_str == "void"

            if params_str and params_str != "void":
                for param_token in params_str.split(","):
                    param_token = param_token.strip()
                    if not param_token:
                        continue
                    is_ptr = "*" in param_token
                    p_parts = param_token.replace("*", " * ").split()
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
                    if "[" in p_type:
                        p_is_arr = True

                    params.append(
                        CParameter(
                            name=p_name,
                            type_name=p_type,
                            is_pointer=is_ptr,
                            line_number=start_line,
                            is_array=p_is_arr,
                        )
                    )

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
            self._analyze_function_body(fn, lines, custom_typedefs, line_map=line_map)
            functions.append(fn)

        return functions

    def _extract_global_vars(
        self,
        lines: List[str],
        functions: List[CFunction],
        custom_typedefs: Optional[Set[str]] = None,
        line_map: Optional[Dict[int, Any]] = None,
    ) -> Dict[str, CVariable]:
        global_vars: Dict[str, CVariable] = {}

        # Avoid materializing every source line covered by every function.
        # Sorted function intervals let us skip function bodies in a single
        # pass over the file while preserving the legacy classification.
        func_ranges = sorted(
            (
                fn.start_line_exp or fn.start_line,
                fn.end_line_exp or fn.end_line,
            )
            for fn in functions
        )
        range_index = 0

        var_decl_regex = re.compile(
            r'^[ \t]*((?:volatile\s+|static\s+|const\s+|unsigned\s+|signed\s+|struct\s+\w+|\w+)\s+(?:\*|\w|\s)*?)\s*(\w+)(?:\[([^\]]*)\])?(?:\s*=\s*([^;]+))?;'
        )

        for line_no_exp, line in enumerate(lines, 1):
            while range_index < len(func_ranges) and line_no_exp > func_ranges[range_index][1]:
                range_index += 1
            if (
                range_index < len(func_ranges)
                and func_ranges[range_index][0] <= line_no_exp <= func_ranges[range_index][1]
            ):
                continue

            line_no = _map_line(line_no_exp, line_map)
            m = var_decl_regex.match(line)
            if not m:
                continue

            type_prefix = m.group(1).strip()
            v_name = m.group(2).strip()
            type_tokens = type_prefix.split()
            if type_tokens and type_tokens[-1] in _STATEMENT_KEYWORDS:
                continue
            if v_name in ("typedef", "#include", "#define", "#ifdef", "#ifndef"):
                continue

            shape = resolve_typedef_shape(type_prefix, self.typedef_shapes) if getattr(self, "typedef_shapes", None) else None
            v_is_array = (m.group(3) is not None) or (shape.is_array if shape else False)
            v_is_pointer = ("*" in type_prefix) or (shape.is_pointer if shape else False)
            v_arr_dim = m.group(3) if m.group(3) is not None else (
                str(shape.array_size) if shape and shape.array_size is not None else None
            )
            global_vars[v_name] = CVariable(
                name=v_name,
                type_name=type_prefix,
                is_pointer=v_is_pointer,
                is_signed=not is_unsigned_type(type_prefix, custom_typedefs),
                is_volatile="volatile" in type_prefix,
                is_vla=False,
                array_size_expr=v_arr_dim,
                has_initializer=m.group(4) is not None,
                declaration_line=line_no,
                is_array=v_is_array,
            )

        return global_vars


ASTAnalyzer = CASTParser

__all__ = ["CASTParser", "ASTAnalyzer"]
