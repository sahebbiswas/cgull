"""Shared builders for interprocedural security-fact tests and benchmarks."""

from types import SimpleNamespace
from typing import Any, Dict

from pycparser import c_parser

from cgull.semantic_models import (
    SemanticLocation,
    SemanticLocationKind,
    SemanticModelRegistry,
    SinkModel,
    SinkRequirement,
    SourceModel,
    SuccessCondition,
    SuccessConditionKind,
    ValidationProperty,
    ValidatorModel,
)


def build_security_models() -> SemanticModelRegistry:
    arg0 = SemanticLocation(SemanticLocationKind.ARGUMENT, 0)
    return SemanticModelRegistry(
        sources={
            "external_read": SourceModel(
                "external_read", (SemanticLocation(SemanticLocationKind.RETURN),)
            ),
            "external_out": SourceModel(
                "external_out",
                (SemanticLocation(SemanticLocationKind.OUTPUT_ARGUMENT, 0),),
            ),
        },
        validators={
            "validate": ValidatorModel(
                "validate",
                arg0,
                ValidationProperty.BOUNDS_CHECKED,
                SuccessCondition(SuccessConditionKind.RETURN_NONZERO),
            )
        },
        sinks={
            "sink": SinkModel(
                "sink",
                (
                    SinkRequirement(
                        arg0, frozenset({ValidationProperty.BOUNDS_CHECKED})
                    ),
                ),
            )
        },
    )


def build_security_context(source: str):
    ast = c_parser.CParser().parse(source)
    functions = []
    globals_: Dict[str, Any] = {}
    for ext in ast.ext:
        if type(ext).__name__ == "FuncDef":
            params = []
            decl_args = getattr(getattr(ext.decl, "type", None), "args", None)
            for param in list(getattr(decl_args, "params", ()) or ()):
                name = getattr(param, "name", None)
                if name:
                    params.append(SimpleNamespace(name=name))
            functions.append(SimpleNamespace(name=ext.decl.name, parameters=params))
        elif (
            type(ext).__name__ == "Decl"
            and type(getattr(ext, "type", None)).__name__ != "FuncDecl"
            and getattr(ext, "name", None)
        ):
            globals_[ext.name] = SimpleNamespace(name=ext.name)
    return SimpleNamespace(
        has_pycparser=True,
        pycparser_ast=ast,
        functions=functions,
        global_variables=globals_,
        line_map=None,
    )
