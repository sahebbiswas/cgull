import sys
import types

# Fix for Windows multiprocessing spawn under pytest when sys.modules['__main__'] lacks __spec__
if sys.platform == "win32":
    main_mod = sys.modules.get("__main__")
    if main_mod and not getattr(main_mod, "__spec__", None):
        setattr(main_mod, "__spec__", types.SimpleNamespace(name="pytest"))
