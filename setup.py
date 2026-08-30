import os
import re
from setuptools import setup, find_packages

with open(os.path.join("cgull", "__init__.py"), "r", encoding="utf-8") as f:
    version = re.search(r'__version__\s*=\s*[\'"]([^\'"]*)[\'"]', f.read()).group(1)

setup(
    name="cgull",
    version=version,
    author="Saheb Biswas",
    author_email="s.b9@yahoo.com",
    description="C-GULL: Code Guardian for Unchecked Logic & Leaks (C Code Security Static Analyzer)",
    long_description=open("README.md", "r", encoding="utf-8").read(),
    long_description_content_type="text/markdown",
    url="https://github.com/sahebbiswas/cgull",
    license="Apache-2.0",
    packages=find_packages(),
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: Apache Software License",
        "Topic :: Security",
        "Topic :: Software Development :: Quality Assurance",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Programming Language :: Python :: 3.13",
        "Programming Language :: Python :: 3.14",
        "Programming Language :: C",
    ],
    python_requires=">=3.10",
    install_requires=[
        # Core runs purely on Python standard library!
        # pycparser is optional for advanced C99 full AST parsing
    ],
    extras_require={
        "ast": ["pycparser>=2.21", "pcpp>=1.30"],
        "preprocess": ["pcpp>=1.30"],
        "dev": ["pytest>=7.0.0", "jsonschema>=4.0.0"],
    },
    entry_points={
        "console_scripts": [
            "cgull=cgull.cli:main",
        ],
    },
)
