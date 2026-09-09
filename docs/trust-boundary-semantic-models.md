# Embedded trust-boundary semantic models

C-GULL semantic models describe firmware call boundaries without teaching individual rules about vendor HALs. Models are project configuration: C-GULL does not infer trust from API names, and an unmodeled or indirect call remains unknown.

## Configuration

Models live under `[semantic_models]` in `.cgull.toml` or `[tool.cgull.semantic_models]` in `pyproject.toml`.

```toml
[[semantic_models.sources]]
function = "mailbox_read"
outputs = ["out:0"]

[[semantic_models.sources]]
function = "mmio_read32"
outputs = ["return"]

[[semantic_models.validators]]
function = "verify_update_signature"
target = "arg:0"
property = "signature_verified"
success = "return_zero"

[[semantic_models.validators]]
function = "check_payload_bounds"
target = "arg:1"
property = "bounds_checked"
success = "return_nonzero"

[[semantic_models.sinks]]
function = "flash_program"
requirements = { "arg:0" = ["authorized"], "arg:1" = ["bounds_checked", "signature_verified"] }
```

Locations are zero-based and use one of three forms:

- `return` — the call return value.
- `arg:N` — the value passed as argument `N`.
- `out:N` — the object written through output-pointer argument `N`.

The initial typed validation properties are `bounds_checked`, `authenticated`, `signature_verified`, `authorized`, and `version_checked`. Properties are intentionally independent: proving `signature_verified` never implies `bounds_checked`, for example.

Validators support `return_zero`, `return_nonzero`, or an exact integer comparison:

```toml
success = { return_equals = 1 }
```

Malformed semantic models are configuration errors. C-GULL fails the configuration instead of silently dropping a security model.

## Per-TU query API

Rules and analysis passes should consume the shared semantic registry through `TUAnalysisSession`, rather than parsing configuration themselves:

```python
from cgull.semantic_models import TUAnalysisSession

session = TUAnalysisSession.from_config(ast_ctx, config)
model = session.model_for_call(cfg_call)

if model.source is not None:
    ...
if model.validator is not None:
    ...
if model.sink is not None:
    ...
```

Only syntactically direct `CFGCall` objects are matched. Indirect calls and direct calls with no configured model return an empty `CallSemanticModel`, preserving conservative unknown semantics.

## Mapping embedded interfaces

Use source models where data first crosses into firmware-controlled state. Common examples include mailbox receives, UART/SPI/I2C reads, DMA completion buffers, MMIO register reads, debug transport receives, and flash reads whose contents are not inherently trusted. Use `return` for scalar-return APIs and `out:N` for receive/output buffers.

Use validator models only when an API establishes one specific security property for a specific value/location. Examples include length/range checks (`bounds_checked`), session or MAC checks (`authenticated`), image signature verification (`signature_verified`), privilege/policy checks (`authorized`), and anti-rollback/version policy checks (`version_checked`). Do not model a parser, checksum, or signature API as proving unrelated properties.

Use sink models for operations where unvalidated data becomes security-sensitive. Typical sinks include DMA programming, flash/update installation, MMIO control writes, debug enable/unlock, mailbox command dispatch, memory-copy lengths, and privileged peripheral configuration. Attach requirements only to the argument locations whose use requires the property.

A representative platform mapping might look like:

| Platform API | Model | Location / property |
| --- | --- | --- |
| `HAL_UART_Receive(..., buf, len, ...)` | source | `out:1` |
| `mailbox_read(msg)` | source | `out:0` |
| `mmio_read32(addr)` | source | `return` |
| `verify_manifest_sig(manifest)` | validator | `arg:0` → `signature_verified` |
| `check_image_version(manifest)` | validator | `arg:0` → `version_checked` |
| `authorize_debug(cmd)` | validator | `arg:0` → `authorized` |
| `flash_program(dst, image, len)` | sink | image/length arguments require project-specific properties |
| `debug_enable(cmd)` | sink | `arg:0` requires `authorized` |

Keep models narrow and auditable. If an API's semantics depend on flags, callback state, complex aliasing, or unsupported protocol state, leave it unmodeled until the analyzer can represent that condition safely.

## Buffer capacity contracts

`CGULL-007` can consume an explicit relationship between a pointer parameter and a
size parameter. Add `buffer_capacities` to the function's call-effect model:

```toml
[[semantic_models.effects]]
function = "process_bytes"
buffer_capacities = [
  { buffer = 0, size = 1, unit = "elements" }
]
```

Argument positions are zero-based. `unit = "elements"` means parameter 1 is the
number of elements addressable through parameter 0, so a strict guard such as
`i < length` can prove `buffer[i]` safe. `unit = "bytes"` is intentionally more
conservative: a direct symbolic index proof is accepted only when the indexed
element is one byte wide. Wider pointee types require an explicit element-count
contract rather than assuming bytes and elements are interchangeable.

C array parameters can express the same relation directly without project
configuration:

```c
void process_bytes(size_t length, unsigned char data[static length]) {
    for (size_t i = 0; i < length; ++i) {
        data[i] = 0;
    }
}
```

C-GULL does not infer capacity from names such as `data`, `size`, or `length`.
A pointer plus an unrelated symbolic comparison remains unproven. Simple local
pointer aliases preserve a capacity fact when all incoming CFG paths agree;
reassigning either the pointer or its contracted size invalidates the fact.
`i <= length` is not a valid proof for an exact `length`-element capacity.

## Pointer interval validators

Add `length = "arg:N"` to a `bounds_checked` validator to establish an accessible
byte interval on its successful branch:

```toml
[[semantic_models.validators]]
function = "validate_range"
target = "arg:0"
length = "arg:1"
property = "bounds_checked"
success = "return_nonzero"
```

This contract means success proves `[ptr, ptr + length)`. Both locations must
be arguments; the length is in bytes. Existing validators without `length`
retain their typed-property behavior. Merely calling a boolean validator and
ignoring its return value establishes no interval proof.

`CGULL-051` consumes these intervals for dereferences, indexing, pointer member
access, `memcpy`, `memmove`, `memcmp`, and configured call-effect
`size_relationships`. Simple aliases and pointer casts preserve the origin.
A successful check on only one path does not establish a proof after a merge;
a fail-closed early return does. Pointer reassignment replaces its facts.
Separate successful checks may cover adjacent intervals of the same origin.