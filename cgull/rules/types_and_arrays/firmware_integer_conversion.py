"""Firmware-facing prioritization for CGULL-049 integer conversions.

The base conversion rule owns correctness: this wrapper only raises the priority
of findings that already exist when their destination is concretely
hardware-like.  Fixed-width integer spellings and typedef names are deliberately
not treated as MMIO evidence.
"""

from typing import Dict, Optional, Set

from ...ast_analyzer import CASTContext
from ...cfg import find_function_def
from ...models import Confidence, Issue, Severity
from .integer_narrowing_cast import IntegerNarrowingCastRule as _BaseIntegerNarrowingCastRule


class IntegerNarrowingCastRule(_BaseIntegerNarrowingCastRule):
    """CGULL-049 with deterministic firmware-facing severity prioritization."""

    @staticmethod
    def _node_has_qualifier(node, qualifier: str) -> bool:
        current = node
        while current is not None:
            if qualifier in (getattr(current, "quals", None) or []):
                return True
            current = getattr(current, "type", None)
        return False

    @staticmethod
    def _variable_for_name(ast_ctx: CASTContext, fn, name: str):
        variable = fn.variables.get(name)
        if variable is not None:
            return variable
        return ast_ctx.global_variables.get(name)

    @classmethod
    def _aggregate_field_traits(cls, ast_ctx: CASTContext) -> Dict[int, Set[str]]:
        """Index volatile/bitfield traits by the existing FieldInfo object.

        FieldInfo intentionally remains unchanged: these traits are only needed
        while prioritizing CGULL-049 findings, so deriving them from pycparser's
        declaration nodes avoids expanding the shared AST model for rule-local
        metadata.
        """
        if not ast_ctx.has_pycparser or ast_ctx.pycparser_ast is None:
            return {}

        from pycparser import c_ast

        traits: Dict[int, Set[str]] = {}

        def mark_aggregate(node, aliases=()):
            definitions = []
            seen = set()
            names = [getattr(node, "name", None), *aliases]
            for name in names:
                if not name:
                    continue
                for key in (name, f"struct {name}", f"union {name}"):
                    definition = ast_ctx.struct_defs.get(key)
                    if definition is not None and id(definition) not in seen:
                        definitions.append(definition)
                        seen.add(id(definition))

            if not definitions:
                return

            for declaration in getattr(node, "decls", None) or []:
                field_name = getattr(declaration, "name", None)
                if not field_name:
                    continue
                field_traits: Set[str] = set()
                if getattr(declaration, "bitsize", None) is not None:
                    field_traits.add("bitfield")
                if cls._node_has_qualifier(declaration, "volatile"):
                    field_traits.add("volatile")
                if not field_traits:
                    continue
                for definition in definitions:
                    field = definition.fields.get(field_name)
                    if field is not None:
                        traits.setdefault(id(field), set()).update(field_traits)

        class AggregateVisitor(c_ast.NodeVisitor):
            def visit_Struct(self, node):
                mark_aggregate(node)
                self.generic_visit(node)

            def visit_Union(self, node):
                mark_aggregate(node)
                self.generic_visit(node)

            def visit_Typedef(self, node):
                current = node.type
                while isinstance(current, (c_ast.PtrDecl, c_ast.ArrayDecl)):
                    current = current.type
                if isinstance(current, c_ast.TypeDecl) and isinstance(
                    current.type, (c_ast.Struct, c_ast.Union)
                ):
                    mark_aggregate(current.type, aliases=(node.name,))
                self.generic_visit(node)

        AggregateVisitor().visit(ast_ctx.pycparser_ast)
        return traits

    @classmethod
    def _firmware_destination_reason(
        cls,
        ast_ctx: CASTContext,
        fn,
        destination,
        field_traits: Dict[int, Set[str]],
    ) -> Optional[str]:
        if destination is None:
            return None

        from pycparser import c_ast

        if isinstance(destination, c_ast.Decl):
            if cls._node_has_qualifier(destination, "volatile"):
                return "a volatile destination"
            name = getattr(destination, "name", None)
            variable = cls._variable_for_name(ast_ctx, fn, name) if name else None
            if variable is not None and variable.is_volatile:
                return "a volatile destination"
            return None

        if isinstance(destination, c_ast.ID):
            variable = cls._variable_for_name(ast_ctx, fn, destination.name)
            if variable is not None and variable.is_volatile:
                return "a volatile destination"
            return None

        if isinstance(destination, c_ast.ArrayRef):
            return cls._firmware_destination_reason(
                ast_ctx, fn, destination.name, field_traits
            )

        if isinstance(destination, c_ast.StructRef):
            base_reason = cls._firmware_destination_reason(
                ast_ctx, fn, destination.name, field_traits
            )
            if base_reason:
                return base_reason

            base_type = ast_ctx.infer_expr_type(destination.name, fn)
            definition = ast_ctx.resolve_struct_def(base_type) if base_type else None
            field_name = getattr(destination.field, "name", None)
            field = definition.fields.get(field_name) if definition and field_name else None
            traits = field_traits.get(id(field), set()) if field is not None else set()
            if "volatile" in traits:
                return "a volatile structure field"
            if "bitfield" in traits:
                return "a bitfield destination"
            return None

        return None

    @classmethod
    def _firmware_priority_lines(cls, ast_ctx: CASTContext) -> Dict[int, str]:
        if not ast_ctx.has_pycparser or ast_ctx.pycparser_ast is None:
            return {}

        from pycparser import c_ast

        field_traits = cls._aggregate_field_traits(ast_ctx)
        priorities: Dict[int, str] = {}

        for fn in ast_ctx.functions:
            funcdef = find_function_def(ast_ctx.pycparser_ast, fn.name)
            if funcdef is None:
                continue

            rule = cls

            class DestinationVisitor(c_ast.NodeVisitor):
                def _record(self, destination, node):
                    reason = rule._firmware_destination_reason(
                        ast_ctx, fn, destination, field_traits
                    )
                    if reason:
                        priorities.setdefault(rule._line_for_node(ast_ctx, node, fn), reason)

                def visit_Decl(self, node):
                    if node.init is not None:
                        self._record(node, node)
                    self.generic_visit(node)

                def visit_Assignment(self, node):
                    self._record(node.lvalue, node)
                    self.generic_visit(node)

            DestinationVisitor().visit(funcdef)

        return priorities

    def scan_ast(self, file_path: str, ast_ctx: CASTContext) -> list[Issue]:
        issues = super().scan_ast(file_path, ast_ctx)
        if not issues:
            return issues

        priorities = self._firmware_priority_lines(ast_ctx)
        for issue in issues:
            reason = priorities.get(issue.line_number)
            if not reason:
                continue
            issue.impact = Severity.HIGH
            if issue.confidence is None:
                issue.confidence = Confidence.FULL
            issue.message = f"{issue.message} Firmware priority: conversion writes to {reason}."
        return issues
