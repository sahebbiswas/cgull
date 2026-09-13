# Analysis header dependency notes

C-GULL requires `pycparser-fake-libc>=2.21` as a separate runtime distribution;
it does not vendor or redistribute that package's headers in its own wheel.
Version 2.21 is a pure Python/resource package with a `py3-none-any` wheel and
no declared Python upper bound. C-GULL uses package resource discovery rather
than assuming an installation directory. Its Python 3.10–3.14 CI matrix runs
the model-resolution and parsing regressions.

The [wrapper repository](https://github.com/ThomasGerstenberg/pycparser-fake-libc)
packages `pycparser/utils/fake_libc_include`. Version 2.21 points to pycparser
commit `3cf6bf5eb16f5eadd4a058e41596145c407a79ad`, whose
[BSD 3-clause license](https://github.com/eliben/pycparser/blob/3cf6bf5eb16f5eadd4a058e41596145c407a79ad/LICENSE)
permits use and redistribution subject to its notice and other conditions.
The wrapper's package metadata reports `License: UNKNOWN` and its repository
has no separate license file; this distinction should be retained in dependency
inventories rather than labeling the wrapper itself BSD-licensed. Any future
vendoring needs a separate license/notice review.

C-GULL's small overlay is original parsing-model code under this repository's
Apache-2.0 license. It is deliberately incomplete and does not copy host libc
or kernel implementation headers. See [configuration](configuration.md#standardposix-and-linux-analysis-headers)
for scope and precedence.
