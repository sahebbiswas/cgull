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
