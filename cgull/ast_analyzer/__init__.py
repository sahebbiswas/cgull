"""C AST analysis public API.

Implementation is housed in focused modules while this package keeps the
historic :mod:`cgull.ast_analyzer` import path stable.
"""

from .pcpp_diagnostics import install_pcpp_diagnostic_suppression

# pcpp's default #error/#warning handling writes directly to stderr.  Install
# C-GULL's integration hook before importing visitor/CASTParser so parser-owned
# preprocessors cannot bypass CLI progress/report coordination.
install_pcpp_diagnostic_suppression()

from .configuration import *
from .preprocessor import *
from .types import *
from .integer_types import *
from .visitor import *
from .callable_signatures import *
from .coverage import CASTParser, ASTAnalyzer, CoverageDegradedError
from .configuration import _PRELUDE_LINE_COUNT, _PYCPARSER_PRELUDE
from .preprocessor import _normalize_macro_dict
from .types import _extract_identifiers_from_ast, _format_pycparser_expr, _format_pycparser_type, _map_line


# The legacy module did not define __all__; retain its observable public API.
__all__ = [name for name in globals() if not name.startswith("__")]
