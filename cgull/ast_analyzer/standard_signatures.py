"""Declarative callable signatures for selected standard C and POSIX APIs.

These models describe callable type shape only.  They intentionally carry no
allocation, ownership, trust, CFG, or call-effect semantics.
"""

from dataclasses import dataclass, field
from typing import Dict, Optional, Sequence


@dataclass(frozen=True)
class StandardCallableParameter:
    """One fixed parameter in a built-in callable signature."""

    name: str
    type_name: str
    is_pointer: bool = False
    is_array: bool = False


@dataclass(frozen=True)
class StandardCallableSignature:
    """Portable declaration metadata for one standard/external API."""

    name: str
    return_type: str
    parameters: Sequence[StandardCallableParameter] = field(default_factory=tuple)
    variadic: bool = False
    provenance: str = "standard-c"


def _p(name: str, type_name: str, *, pointer: bool = False, array: bool = False) -> StandardCallableParameter:
    return StandardCallableParameter(name=name, type_name=type_name, is_pointer=pointer, is_array=array)


# Keep this registry deliberately small and reviewable.  Width-sensitive types
# remain symbolic (for example ``size_t`` and ``ssize_t``) so consumers resolve
# them through C-GULL's configured type-width model rather than the Python host.
_STANDARD_CALLABLE_SIGNATURES: Dict[str, StandardCallableSignature] = {
    "malloc": StandardCallableSignature(
        name="malloc",
        return_type="void *",
        parameters=(_p("size", "size_t"),),
    ),
    "memcpy": StandardCallableSignature(
        name="memcpy",
        return_type="void *",
        parameters=(
            _p("dest", "void *", pointer=True),
            _p("src", "const void *", pointer=True),
            _p("count", "size_t"),
        ),
    ),
    "memmove": StandardCallableSignature(
        name="memmove",
        return_type="void *",
        parameters=(
            _p("dest", "void *", pointer=True),
            _p("src", "const void *", pointer=True),
            _p("count", "size_t"),
        ),
    ),
    "strncpy": StandardCallableSignature(
        name="strncpy",
        return_type="char *",
        parameters=(
            _p("dest", "char *", pointer=True),
            _p("src", "const char *", pointer=True),
            _p("count", "size_t"),
        ),
    ),
    "snprintf": StandardCallableSignature(
        name="snprintf",
        return_type="int",
        parameters=(
            _p("buffer", "char *", pointer=True),
            _p("buffer_size", "size_t"),
            _p("format", "const char *", pointer=True),
        ),
        variadic=True,
    ),
    "read": StandardCallableSignature(
        name="read",
        return_type="ssize_t",
        parameters=(
            _p("fd", "int"),
            _p("buffer", "void *", pointer=True),
            _p("count", "size_t"),
        ),
        provenance="posix",
    ),
}


def standard_callable_signature(name: str) -> Optional[StandardCallableSignature]:
    """Return built-in signature metadata for ``name``, if explicitly modeled."""

    return _STANDARD_CALLABLE_SIGNATURES.get(name)


def standard_callable_signature_names() -> Sequence[str]:
    """Return modeled names in deterministic order for documentation/tests."""

    return tuple(sorted(_STANDARD_CALLABLE_SIGNATURES))
