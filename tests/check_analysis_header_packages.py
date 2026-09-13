"""Build/install wheel and sdist and validate runtime model resource discovery.

Run explicitly in packaging CI: python tests/check_analysis_header_packages.py
Requires the standard build tools (setuptools, wheel) and runtime dependencies.
"""

import os
from pathlib import Path
import subprocess
import sys
import tempfile

from setuptools import build_meta


PROBE = r'''
from pathlib import Path
from importlib.metadata import requires
from cgull.analysis_headers import analysis_header_roots
from cgull.includes import expand_includes
from cgull.ast_analyzer import CASTParser
roots = analysis_header_roots()
assert all(Path(root).is_dir() for root in roots)
assert Path(roots[0], 'linux/if.h').is_file()
assert any(r.startswith('pycparser-fake-libc>=2.21') for r in requires('cgull'))
source = ('#include <pthread.h>\n#include <dlfcn.h>\n#include <shadow.h>\n'
          '#include <linux/if.h>\n'
          'void f(void) { pthread_t t; Dl_info d; struct spwd *s; struct ifreq r; }\n')
assert CASTParser().parse(expand_includes(source)).parse_tier == 'pcpp+pycparser'
print('Installed resource and parsing check passed:', roots)
'''


def main():
    with tempfile.TemporaryDirectory(prefix="cgull-model-packaging-") as directory:
        out = Path(directory)
        artifacts = (build_meta.build_wheel(directory), build_meta.build_sdist(directory))
        for index, archive in enumerate(artifacts):
            target = out / f"installed-{index}"
            subprocess.run([
                sys.executable, "-m", "pip", "install", "--no-deps",
                "--no-build-isolation", "--target", str(target), str(out / archive),
            ], check=True)
            subprocess.run(
                [sys.executable, "-c", PROBE], cwd=out,
                env={**os.environ, "PYTHONPATH": str(target)}, check=True,
            )


if __name__ == "__main__":
    main()
