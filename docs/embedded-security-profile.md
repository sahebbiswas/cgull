# Embedded security semantic-model profile

CGULL-047 is intentionally model-driven: it does not guess trust boundaries from
function-name substrings.  The opt-in `embedded-security` profile provides a
versioned set of conservative, canonical firmware API *shapes* that projects can
use directly or extend with their own HAL names.

## Enable the profile

```toml
schema_version = 1

[semantic_models]
profiles = ["embedded-security"]
```

The current built-in `embedded-security` profile version is **1**.  Its version
is pinned in `cgull.semantic_model_profiles.EMBEDDED_SECURITY_PROFILE_VERSION`
and covered by tests.  Profile evolution must preserve conservative semantics;
a breaking contract should be introduced as a new profile/version rather than
silently changing what an existing validator means.

## Built-in semantic knowledge

Enabling the profile explicitly opts into these canonical contracts.  CGULL does
not infer equivalent vendor APIs by spelling.

| Trust-boundary family | Canonical profile contracts |
| --- | --- |
| Mailbox / host IPC | source `mailbox_receive` |
| UART / SPI / I2C input | sources `uart_receive`, `spi_receive`, `i2c_receive` |
| Less-trusted DMA input | source `dma_descriptor_receive`, sink `dma_start` |
| Firmware/update input | sources `firmware_image_receive`, `update_manifest_receive` |
| Flash / NVRAM mutation | sinks `flash_write`, `flash_erase`, `nvram_write` |
| MMIO/register mutation | sink `mmio_write` |
| Debug/JTAG/diagnostic enablement | sink `debug_enable` |
| Boot/update acceptance | sinks `boot_image_accept`, `update_activate` |

The profile also models the stable POSIX-style input APIs `read`, `recv`, and
`recvfrom` as sources for the buffer written through argument 1.  Their return
byte count is not modeled as externally controlled data.

Typed validator contracts are provided for bounds/range checks
(`validate_bounds`, `validate_range`), authentication (`authenticate_request`),
authorization (`authorize_request`), signature verification (`verify_signature`),
version/rollback checks (`check_version`, `check_rollback`), and allowlist checks
(`check_allowlist`).  These names are contracts, not heuristics: CGULL trusts a
validator only when the profile or project configuration explicitly declares it.

## Overlay a project HAL

Most firmware will not use the canonical names.  Add platform mappings alongside
the profile; no CGULL-047 rule change is required:

```toml
[semantic_models]
profiles = ["embedded-security"]

[[semantic_models.sources]]
function = "soc_mbox_read"
outputs = ["out:1"]

[[semantic_models.validators]]
function = "platform_acl_check"
target = "arg:0"
property = "authorized"
success = "return_zero"

[[semantic_models.sinks]]
function = "qspi_program_page"
requirements = { "arg:0" = ["bounds_checked", "authorized"] }
```

Project entries are additive.  A project entry that tries to redefine a function
already defined by the selected profile is rejected as a configuration error;
CGULL never silently replaces a security contract.

Do not map a function as a validator unless successful return really guarantees
the declared property on the modeled target.  Leaving an uncertain API unknown
may produce a finding; falsely declaring validation can suppress a real one.

## Firmware-style example

`examples/embedded-security/` contains a self-contained configuration and C
fixture with paired unsafe/safe flows for mailbox-to-flash, UART/SPI/I2C-driven
register or persistent writes, DMA descriptors, firmware/update activation, and
authenticated debug enablement.  The safe variants establish every sink-required
property on the sink-reaching path; the unsafe variants intentionally omit one
or more required properties.
