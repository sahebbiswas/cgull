"""Nested FuncDef statics must not attach to the enclosing function."""

from pycparser import c_ast

from cgull.rules.memory_management.helpers import _static_local_names


def _static_int_decl(name: str) -> c_ast.Decl:
    return c_ast.Decl(
        name=name,
        quals=[],
        align=[],
        storage=["static"],
        funcspec=[],
        type=c_ast.TypeDecl(
            declname=name,
            quals=[],
            align=None,
            type=c_ast.IdentifierType(names=["int"]),
        ),
        init=None,
        bitsize=None,
    )


def test_nested_funcdef_statics_are_not_registered_on_enclosing():
    # Synthesize a GNU-style nested FuncDef; pycparser's C parser rejects them.
    nested = c_ast.FuncDef(
        decl=c_ast.Decl(
            name="nested",
            quals=[],
            align=[],
            storage=[],
            funcspec=[],
            type=c_ast.FuncDecl(
                args=c_ast.ParamList(
                    [
                        c_ast.Typename(
                            name=None,
                            quals=[],
                            align=None,
                            type=c_ast.TypeDecl(
                                declname=None,
                                quals=[],
                                align=None,
                                type=c_ast.IdentifierType(names=["void"]),
                            ),
                        )
                    ]
                ),
                type=c_ast.TypeDecl(
                    declname="nested",
                    quals=[],
                    align=None,
                    type=c_ast.IdentifierType(names=["int"]),
                ),
            ),
            init=None,
            bitsize=None,
        ),
        param_decls=None,
        body=c_ast.Compound(block_items=[_static_int_decl("inner_only")]),
    )
    outer = c_ast.FuncDef(
        decl=c_ast.Decl(
            name="outer",
            quals=[],
            align=[],
            storage=[],
            funcspec=[],
            type=c_ast.FuncDecl(
                args=c_ast.ParamList(
                    [
                        c_ast.Typename(
                            name=None,
                            quals=[],
                            align=None,
                            type=c_ast.TypeDecl(
                                declname=None,
                                quals=[],
                                align=None,
                                type=c_ast.IdentifierType(names=["void"]),
                            ),
                        )
                    ]
                ),
                type=c_ast.TypeDecl(
                    declname="outer",
                    quals=[],
                    align=None,
                    type=c_ast.IdentifierType(names=["int"]),
                ),
            ),
            init=None,
            bitsize=None,
        ),
        param_decls=None,
        body=c_ast.Compound(block_items=[_static_int_decl("keep"), nested]),
    )
    names = _static_local_names(outer)
    assert "keep" in names
    assert "inner_only" not in names
