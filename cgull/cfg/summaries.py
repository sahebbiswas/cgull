"""Interprocedural function summaries."""

from typing import Dict, Optional, Set

from ..ast_analyzer import _format_pycparser_expr
from .construction import _guarded_expression_uses, _is_nullish, build_cfg, find_function_def
from .dataflow import meet_nullness
from .model import Allocation, FunctionSummary, Nullness


def _unwrap_cast(node):
    while node is not None and type(node).__name__ in {"Cast", "ExprList"}:
        if type(node).__name__ == "Cast":
            node = node.expr
        else:
            node = node.exprs[-1] if getattr(node, "exprs", None) else None
    return node


def _get_builtin_summaries(alloc_funcs: Optional[Set[str]] = None, dealloc_funcs: Optional[Set[str]] = None, realloc_funcs: Optional[Set[str]] = None) -> Dict[str, FunctionSummary]:
    alloc_set = alloc_funcs if alloc_funcs is not None else {"malloc", "calloc", "realloc", "aligned_alloc", "strdup", "strndup", "valloc", "pvalloc", "memalign"}
    dealloc_set = dealloc_funcs if dealloc_funcs is not None else {"free", "cfree", "vfree"}
    if realloc_funcs:
        alloc_set.update(realloc_funcs)

    builtins: Dict[str, FunctionSummary] = {}
    for f in dealloc_set:
        builtins[f] = FunctionSummary(freed_params={0}, return_nullness=Nullness.UNKNOWN, returns_allocation=False)
    for f in alloc_set:
        builtins[f] = FunctionSummary(freed_params=set(), return_nullness=Nullness.MAYBE_NULL, returns_allocation=True)
    return builtins


def analyze_function_summaries(ast_ctx, alloc_funcs: Optional[Set[str]] = None, dealloc_funcs: Optional[Set[str]] = None, realloc_funcs: Optional[Set[str]] = None) -> Dict[str, FunctionSummary]:
    """
    Computes intra-file interprocedural function summaries for all functions defined in ast_ctx.
    Performs fixed-point iteration to propagate parameter deallocations and return values across callers/callees.
    """
    summaries: Dict[str, FunctionSummary] = _get_builtin_summaries(alloc_funcs=alloc_funcs, dealloc_funcs=dealloc_funcs, realloc_funcs=realloc_funcs)

    if not hasattr(ast_ctx, "functions") or not ast_ctx.functions:
        return summaries

    # Map function name to CFunction
    fn_map = {fn.name: fn for fn in ast_ctx.functions if getattr(fn, "name", None)}

    # Initialize summaries for all user-defined functions
    for name in fn_map:
        if name not in summaries:
            summaries[name] = FunctionSummary()

    # Fixed-point iteration
    changed = True
    max_iters = len(fn_map) * 3 + 10
    iters = 0

    while changed and iters < max_iters:
        changed = False
        iters += 1

        for name, fn in fn_map.items():
            old_summary = summaries[name]
            param_names = [p.name for p in fn.parameters if p.name]

            # Build CFG using current summaries
            cfg = None
            if getattr(ast_ctx, "has_pycparser", False) and ast_ctx.pycparser_ast is not None:
                funcdef = find_function_def(ast_ctx.pycparser_ast, name)
                if funcdef is not None:
                    cfg = build_cfg(funcdef, alloc_funcs=alloc_funcs, dealloc_funcs=dealloc_funcs, realloc_funcs=realloc_funcs, summaries=summaries, line_map=getattr(ast_ctx, "line_map", None))

            freed_params: Set[int] = set()
            unsafe_deref_params: Set[int] = set()
            return_nullness_set: Set[Nullness] = set()
            returns_alloc: bool = False

            if cfg is not None:
                initial_initialized = set(p.name for p in fn.parameters if p.name) | set(getattr(ast_ctx, "global_variables", {}).keys()) | {var.name for var in fn.variables.values() if getattr(var, "has_initializer", False) and var.name}
                cfg.analyze_dataflow(initial_nonnull=set(), initial_initialized=initial_initialized)

                # Check parameter deallocation
                for i, p_name in enumerate(param_names):
                    for node in cfg.nodes.values():
                        if p_name in node.freed:
                            freed_params.add(i)
                            break

                # A callee can require an allocation result to be checked by
                # its caller. Track the parameter's incoming location rather
                # than its variable name so ``p = q; *p`` is attributed to q,
                # not to p. Unknown/external callees intentionally produce no
                # fact.
                for i, p_name in enumerate(param_names):
                    param_location = f"var_{p_name}"
                    for node in cfg.nodes.values():
                        loc_map = cfg.get_loc_map_at_node(node.node_id)
                        for use_kind, payload, guarded_nonnull in _guarded_expression_uses(getattr(node, "_ast_node", None)):
                            if use_kind == "deref":
                                deref_var = payload
                                if param_location in loc_map.get(deref_var, set()) and \
                                   deref_var not in guarded_nonnull and \
                                   cfg.query_nullness(deref_var, node.node_id) != Nullness.NON_NULL:
                                    unsafe_deref_params.add(i)
                                    break
                                continue

                            callee = _format_pycparser_expr(payload.name)
                            callee_summary = summaries.get(callee)
                            args = list(getattr(payload.args, "exprs", []) or []) if payload.args else []
                            if not callee_summary:
                                continue
                            for arg_index in callee_summary.unsafe_deref_params:
                                if arg_index >= len(args):
                                    continue
                                arg = _unwrap_cast(args[arg_index])
                                if type(arg).__name__ != "ID":
                                    continue
                                arg_name = str(arg.name)
                                if param_location in loc_map.get(arg_name, set()) and \
                                   arg_name not in guarded_nonnull and \
                                   cfg.query_nullness(arg_name, node.node_id) != Nullness.NON_NULL:
                                    unsafe_deref_params.add(i)
                                    break
                            if i in unsafe_deref_params:
                                break
                        if i in unsafe_deref_params:
                            break

                # Inspect return statements
                for node in cfg.nodes.values():
                    if node.kind == "return":
                        ret_expr = node.expr_str.strip()
                        ret_ast = getattr(node, "_ast_node", None)
                        expr_ast = getattr(ret_ast, "expr", None) if ret_ast is not None else None

                        ret_nullness = Nullness.UNKNOWN
                        if ret_expr in param_names:
                            ret_nullness = cfg.query_nullness(ret_expr, node.node_id)
                        elif ret_expr in fn.variables:
                            ret_nullness = cfg.query_nullness(ret_expr, node.node_id)
                            if cfg.query_allocation(ret_expr, node.node_id) in (Allocation.ALLOCATED, Allocation.MAYBE_ALLOCATED):
                                returns_alloc = True
                                if ret_nullness == Nullness.UNKNOWN:
                                    ret_nullness = Nullness.MAYBE_NULL
                        elif expr_ast is not None and type(expr_ast).__name__ == "FuncCall":
                            callee = _format_pycparser_expr(expr_ast.name)
                            callee_summary = summaries.get(callee)
                            if callee_summary:
                                ret_nullness = callee_summary.return_nullness
                                if callee_summary.returns_allocation:
                                    returns_alloc = True
                        elif expr_ast is not None and _is_nullish(expr_ast):
                            ret_nullness = Nullness.NULL
                        elif ret_expr in {"NULL", "nullptr", "0", "0x0", "(void*)0", "(void *)0"}:
                            ret_nullness = Nullness.NULL

                        return_nullness_set.add(ret_nullness)

            # Combine return nullness facts across return branches
            if not return_nullness_set:
                final_ret_nullness = Nullness.UNKNOWN
            else:
                final_ret_nullness = None
                for rn in return_nullness_set:
                    if final_ret_nullness is None:
                        final_ret_nullness = rn
                    else:
                        final_ret_nullness = meet_nullness(final_ret_nullness, rn)

            new_summary = FunctionSummary(
                freed_params=freed_params,
                unsafe_deref_params=unsafe_deref_params,
                return_nullness=final_ret_nullness if final_ret_nullness is not None else Nullness.UNKNOWN,
                returns_allocation=returns_alloc,
                is_unknown=False,
            )

            if new_summary != old_summary:
                summaries[name] = new_summary
                changed = True

    return summaries
