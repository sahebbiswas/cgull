"""Possible reverse accesses below an explicitly aliased base, independent of
exact allocation bounds. Offsets are in elements; pointer casts lose the proof.
Loop heads widen descending offsets, then replay once to publish observations.
"""
from dataclasses import dataclass, replace
from math import inf

from pycparser import c_ast


@dataclass(frozen=True)
class ReverseFact:
    origin: str
    lower: float = 0
    derived: bool = False
    reverse: bool = False


@dataclass(frozen=True)
class ReverseAccess:
    node: object
    origin: str
    write: bool


def reverse_walk_accesses(funcdef, initial_facts):
    """Return potential lower-bound accesses, never definite object violations.

    Incoming pointers alone do not establish a logical boundary. An explicit
    alias/derivation establishes the base relationship used by this domain.
    Unsupported jumps, shadowing and address escapes conservatively lose facts.
    """
    names = set()
    unsupported = False
    has_reverse = False

    class Check(c_ast.NodeVisitor):
        def visit_UnaryOp(self, node):
            nonlocal has_reverse
            has_reverse |= node.op in ('--', 'p--')
            self.generic_visit(node)

        def visit_Assignment(self, node):
            nonlocal has_reverse
            has_reverse |= node.op == '-='
            self.generic_visit(node)

        def visit_BinaryOp(self, node):
            nonlocal has_reverse
            has_reverse |= node.op == '-'
            self.generic_visit(node)

        def visit_Decl(self, node):
            nonlocal unsupported
            if node.name:
                if node.name in names:
                    unsupported = True
                names.add(node.name)
            self.generic_visit(node)

        def visit_Goto(self, node):
            nonlocal unsupported
            unsupported = True

        visit_Switch = visit_Goto
        visit_Label = visit_Goto

    Check().visit(funcdef)
    if unsupported or not has_reverse:
        return ()
    events = {}

    def merge(a, b):
        return {k: replace(v, lower=min(v.lower, b[k].lower),
                           derived=v.derived and b[k].derived,
                           reverse=v.reverse or b[k].reverse)
                for k, v in a.items() if k in b and v.origin == b[k].origin}

    def constant(node):
        from .pointer_ranges import _constant_int
        return _constant_int(node)

    def refine(node, env, truth=True):
        if isinstance(node, c_ast.UnaryOp) and node.op == '!':
            return refine(node.expr, env, not truth)
        if not isinstance(node, c_ast.BinaryOp):
            return
        if (node.op == '&&' and truth) or (node.op == '||' and not truth):
            # A pre-update guard cannot be reapplied to the post-update cursor.
            changed = set()

            class Mutations(c_ast.NodeVisitor):
                def visit_UnaryOp(self, update):
                    if update.op in ('++', '--', 'p++', 'p--', '&') and isinstance(update.expr, c_ast.ID):
                        changed.add(update.expr.name)
                    self.generic_visit(update)

                def visit_Assignment(self, update):
                    if isinstance(update.lvalue, c_ast.ID):
                        changed.add(update.lvalue.name)
                    self.generic_visit(update)

            Mutations().visit(node.right)
            stable = {k: v for k, v in env.items() if k not in changed}
            refine(node.left, stable, truth)
            env.update(stable)
            refine(node.right, env, truth)
            return
        if not isinstance(node.left, c_ast.ID) or not isinstance(node.right, c_ast.ID):
            return
        left, right, op = node.left.name, node.right.name, node.op
        if not truth:
            op = {'>': '<=', '>=': '<', '<': '>=', '<=': '>', '==': '!=', '!=': '=='}.get(op)
        if op in ('<', '<='):
            left, right = right, left
            op = '>' if op == '<' else '>='
        a, b = env.get(left), env.get(right)
        if a and b and a.origin == b.origin and op in ('>', '>=', '=='):
            env[left] = replace(a, lower=max(a.lower, b.lower + (op == '>')))

    def expression(node, env, publish, write=False):
        if node is None:
            return None
        if isinstance(node, c_ast.ID):
            return env.get(node.name)
        if isinstance(node, c_ast.Cast):
            expression(node.expr, env, publish)
            return None  # Different strides require byte-level modelling.
        if isinstance(node, c_ast.UnaryOp):
            if node.op in ('sizeof', '_Alignof'):
                return None
            if node.op == '&':
                if isinstance(node.expr, c_ast.ID):
                    env.pop(node.expr.name, None)
                return None
            value = expression(node.expr, env, publish, node.op in ('--', 'p--', '++', 'p++'))
            if node.op in ('--', 'p--', '++', 'p++') and isinstance(node.expr, c_ast.ID) and value:
                updated = replace(value, lower=value.lower + (-1 if '--' in node.op else 1),
                                  reverse=value.reverse or '--' in node.op)
                env[node.expr.name] = updated
                return value if node.op.startswith('p') else updated
            if node.op == '*':
                access(node, value, publish, write)
                return None
            return None
        if isinstance(node, c_ast.ArrayRef):
            value = expression(node.name, env, publish)
            expression(node.subscript, env, publish)
            amount = constant(node.subscript)
            if value and amount is not None:
                access(node, replace(value, lower=value.lower + amount), publish, write)
            return None
        if isinstance(node, c_ast.BinaryOp):
            value = expression(node.left, env, publish)
            if node.op in ('&&', '||'):
                known = constant(node.left)
                if known is not None and bool(known) != (node.op == '&&'):
                    return None
                skipped = dict(env)
                refine(node.left, env, node.op == '&&')
                expression(node.right, env, publish)
                joined = merge(skipped, env)
                env.clear()
                env.update(joined)
                return None
            other = expression(node.right, env, publish)
            if node.op in ('+', '-') and value and not other:
                amount = constant(node.right)
                # strlen(base) can be zero; no positive minimum is implied.
                is_length = (isinstance(node.right, c_ast.FuncCall)
                             and isinstance(node.right.name, c_ast.ID)
                             and node.right.name.name == 'strlen'
                             and node.right.name.name not in names
                             and len(getattr(node.right.args, 'exprs', ()) or ()) == 1
                             and isinstance(node.right.args.exprs[0], c_ast.ID)
                             and node.right.args.exprs[0].name == value.origin)
                delta = amount if amount is not None else (0 if is_length and node.op == '+' else -inf)
                if node.op == '-' and amount is not None:
                    delta = -amount
                return replace(value, lower=value.lower + delta, derived=True,
                               reverse=value.reverse or (node.op == '-' and amount is not None and amount > 0))
            return None
        if isinstance(node, c_ast.Assignment):
            value = expression(node.rvalue, env, publish)
            if isinstance(node.lvalue, c_ast.ID):
                name = node.lvalue.name
                if node.op in ('-=', '+=') and name in env:
                    amount = constant(node.rvalue)
                    old = env[name]
                    delta = amount * (-1 if node.op == '-=' else 1) if amount is not None else -inf
                    value = replace(old, lower=old.lower + delta, reverse=old.reverse or node.op == '-=')
                elif node.op != '=':
                    value = None
                if value:
                    env[name] = replace(value, derived=value.derived or name != value.origin)
                else:
                    env.pop(name, None)
            else:
                expression(node.lvalue, env, publish, True)
            return value
        if isinstance(node, c_ast.TernaryOp):
            expression(node.cond, env, publish)
            a, b = dict(env), dict(env)
            refine(node.cond, a)
            refine(node.cond, b, False)
            expression(node.iftrue, a, publish)
            expression(node.iffalse, b, publish)
            env.clear()
            env.update(merge(a, b))
            return None
        for _, child in node.children():
            expression(child, env, publish)
        return None

    def access(node, value, publish, write):
        if publish and value and value.derived and value.reverse and value.lower < 0:
            events[id(node)] = ReverseAccess(node, value.origin, write)

    def statement(node, env, publish):
        if node is None:
            return env, ''
        if isinstance(node, (c_ast.Compound, c_ast.DeclList)):
            for item in (node.block_items if isinstance(node, c_ast.Compound) else node.decls) or ():
                env, flow = statement(item, env, publish)
                if flow:
                    return env, flow
            return env, ''
        if isinstance(node, c_ast.Decl):
            value = expression(node.init, env, publish)
            if isinstance(node.type, c_ast.ArrayDecl):
                value = ReverseFact(node.name)
            if value:
                env[node.name] = replace(value, derived=value.derived or node.name != value.origin)
            else:
                env.pop(node.name, None)
            return env, ''
        if isinstance(node, c_ast.If):
            expression(node.cond, env, publish)
            known = constant(node.cond)
            if known is not None:
                return statement(node.iftrue if known else node.iffalse, env, publish)
            a, b = dict(env), dict(env)
            refine(node.cond, a)
            refine(node.cond, b, False)
            a, af = statement(node.iftrue, a, publish)
            b, bf = statement(node.iffalse, b, publish)
            if af and not bf:
                return b, ''
            if bf and not af:
                return a, ''
            return merge(a, b), af if af == bf else 'stop' if af and bf else ''
        if isinstance(node, (c_ast.While, c_ast.DoWhile, c_ast.For)):
            if isinstance(node, c_ast.For):
                env, _ = statement(node.init, env, publish)
            condition = constant(node.cond)
            if condition == 0 and not isinstance(node, c_ast.DoWhile):
                return env, ''
            entry, head = dict(env), dict(env)

            def trip(current, emit):
                if not isinstance(node, c_ast.DoWhile):
                    expression(node.cond, current, emit)
                    refine(node.cond, current)
                current, flow = statement(node.stmt, current, emit)
                if flow in ('break', 'return', 'stop'):
                    return current, flow
                if isinstance(node, c_ast.For):
                    expression(node.next, current, emit)
                if isinstance(node, c_ast.DoWhile):
                    expression(node.cond, current, emit)
                    refine(node.cond, current)
                return current, ''

            if condition == 0:
                final, flow = trip(dict(head), publish)
                return final, 'return' if flow == 'return' else ''

            # Descending bounds widen immediately; origins/aliases only disappear.
            # Each remaining variable can disappear once, so this terminates.
            while True:
                back, flow = trip(dict(head), False)
                if flow:
                    break
                joined = merge(entry, back)
                for key, value in list(joined.items()):
                    if key in head and value.lower < head[key].lower:
                        joined[key] = replace(value, lower=-inf)
                if joined == head:
                    break
                head = joined
            final, flow = trip(dict(head), publish)
            return merge(entry, final), ''
        expression(node, env, publish)
        flow = {c_ast.Break: 'break', c_ast.Continue: 'continue', c_ast.Return: 'return'}.get(type(node), '')
        return env, flow

    env = {name: ReverseFact(fact.origin) for name, fact in initial_facts.items()
           if fact.origin and fact.element_width is not None}
    statement(funcdef.body, env, True)
    return tuple(events.values())
