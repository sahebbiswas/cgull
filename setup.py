from setuptools import setup, find_packages

setup(
    name="cgull",
    version="1.0.0",
    author="Saheb Biswas",
    author_email="s.b9@yahoo.com",
    description="C-GULL: Code Guardian for Unchecked Logic & Leaks (C Code Security Static Analyzer)",
    long_description=open("README.md", "r", encoding="utf-8").read(),
    long_description_content_type="text/markdown",
    url="https://github.com/sahebbiswas/cgull",
    packages=find_packages(),
    classifiers=[
        "Development Status :: 5 - Production/Stable",
        "Intended Audience :: Developers",
        "Topic :: Security",
        "Topic :: Software Development :: Quality Assurance",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Programming Language :: C",
    ],
    python_requires=">=3.8",
    install_requires=[
        # Core runs purely on Python standard library!
        # pycparser is optional for advanced C99 full AST parsing
    ],
    extras_require={
        "ast": ["pycparser>=2.21"],
        "dev": ["pytest>=7.0.0", "flake8>=5.0.0"],
    },
    entry_points={
        "console_scripts": [
            "cgull=cgull.cli:main",
        ],
    },
)
