"""Conservative CFG identities for repeated unresolved bounds obligations."""
from collections import Counter, deque

from pycparser import c_ast

from .array_bounds_guards import event_expression


def walk(node):
    if node is not None:
        yield node
        for _, child in node.children():
            yield from walk(child)


class BoundsObligations:
    """Group only simple, unique automatic bindings with identical CFG epochs.

    Ambiguous bindings, escaped addresses and compound access expressions keep
    per-access identity. Epochs are reaching barrier sets, not source order;
    branches and loops therefore cannot reuse an earlier definition by accident.
    """

    def __init__(self, cfg, funcdef):
        self.cfg = cfg
        nodes = list(walk(funcdef))
        self.declarations = Counter(n.name for n in nodes if isinstance(n, c_ast.Decl))
        self.unsafe = {n.name for n in nodes if isinstance(n, c_ast.Decl)
                       and ("static" in n.storage or "extern" in n.storage or "volatile" in n.quals)}
        for node in nodes:
            if isinstance(node, c_ast.UnaryOp) and node.op == "&":
                self.unsafe.update(n.name for n in walk(node.expr) if isinstance(n, c_ast.ID))
        self.has_goto = any(isinstance(n, c_ast.Goto) for n in nodes)
        self.event_nodes = {node_id: list(walk(event_expression(event)))
                            for node_id, event in cfg.nodes.items()}
        self.cache = {}

    def key(self, access, event_id, capacity):
        if not isinstance(access.name, c_ast.ID) or not isinstance(access.subscript, c_ast.ID):
            return (id(access),)
        names = (access.name.name, access.subscript.name)
        if self.has_goto or event_id is None or any(self.declarations[n] != 1 or n in self.unsafe for n in names):
            return (id(access),)
        if names not in self.cache:
            self.cache[names] = self._epochs(names)
        incoming, barriers = self.cache[names]
        if event_id in barriers or event_id not in incoming:
            return (id(access),)
        return names, capacity, incoming[event_id]

    def _epochs(self, names):
        def passes_base(node):
            if isinstance(node, c_ast.ArrayRef):
                return False
            if isinstance(node, c_ast.ID):
                return node.name == names[0]
            return node is not None and any(passes_base(child) for _, child in node.children())

        cfg = self.cfg
        barriers = set()
        for node_id, event in cfg.nodes.items():
            nodes = self.event_nodes[node_id]
            # Passing the base itself may release/reallocate its object.
            if any(isinstance(n, c_ast.FuncCall) and n.args and
                   any(passes_base(arg) for arg in n.args.exprs) for n in nodes):
                barriers.add(node_id)
            if any(isinstance(n, (c_ast.Goto, c_ast.Label)) for n in nodes):
                barriers.add(node_id)
            # Other scalars may supply a relational bound or capacity contract.
            # Treat their writes as barriers too rather than guessing dependencies.
            if any(isinstance(n, c_ast.Assignment) and not isinstance(n.lvalue, c_ast.ArrayRef)
                   for n in nodes):
                barriers.add(node_id)
            if any(isinstance(n, c_ast.UnaryOp) and n.op in {"++", "--", "p++", "p--"}
                   for n in nodes):
                barriers.add(node_id)
            if any(isinstance(n, c_ast.Decl) for n in nodes):
                barriers.add(node_id)
            # A scalar comparison can establish/change a partial bounds proof.
            # Reading a[i] in a condition does not itself validate i.
            if any(isinstance(n, c_ast.BinaryOp) and n.op in {"<", "<=", ">", ">=", "==", "!="}
                   and any(isinstance(side, c_ast.ID)
                           for side in (n.left, n.right)) for n in nodes):
                barriers.add(node_id)
        incoming = {cfg.entry: frozenset({("entry",)})}
        queue = deque([cfg.entry])
        while queue:
            node_id = queue.popleft()
            if node_id not in cfg.nodes:
                continue
            for successor in cfg.nodes[node_id].successors:
                state = frozenset({(node_id, successor)}) if node_id in barriers else incoming[node_id]
                merged = incoming.get(successor, frozenset()) | state
                if successor not in incoming or merged != incoming[successor]:
                    incoming[successor] = merged
                    queue.append(successor)
        return incoming, barriers
