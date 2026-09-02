"""Built-in semantic-model profiles.

Profiles are deliberately explicit collections of call contracts.  They do not
perform function-name inference.  Enabling a profile means opting in to the
canonical API names below; projects with different HAL names should add normal
``[[semantic_models.*]]`` entries alongside the profile.
"""

from __future__ import annotations

from copy import deepcopy
from typing import Dict, Mapping


EMBEDDED_SECURITY_PROFILE = "embedded-security"
EMBEDDED_SECURITY_PROFILE_VERSION = 1


# Canonical trust-boundary shapes for security-focused embedded firmware.
# These names are intentionally generic profile contracts rather than guessed
# vendor APIs.  A project opts into them explicitly by enabling the profile.
_EMBEDDED_SECURITY_V1 = {
    "sources": [
        {"function": "mailbox_receive", "outputs": ["out:0"]},
        {"function": "uart_receive", "outputs": ["out:0"]},
        {"function": "spi_receive", "outputs": ["out:0"]},
        {"function": "i2c_receive", "outputs": ["out:0"]},
        {"function": "dma_descriptor_receive", "outputs": ["out:0"]},
        {"function": "firmware_image_receive", "outputs": ["out:0"]},
        {"function": "update_manifest_receive", "outputs": ["out:0"]},
        # Stable POSIX-style input APIs.  The buffer object is the untrusted
        # output; the byte-count return value is intentionally not tainted.
        {"function": "read", "outputs": ["out:1"]},
        {"function": "recv", "outputs": ["out:1"]},
        {"function": "recvfrom", "outputs": ["out:1"]},
    ],
    "validators": [
        {
            "function": "validate_bounds",
            "target": "arg:0",
            "property": "bounds_checked",
            "success": "return_nonzero",
        },
        {
            "function": "validate_range",
            "target": "arg:0",
            "property": "bounds_checked",
            "success": "return_nonzero",
        },
        {
            "function": "authenticate_request",
            "target": "arg:0",
            "property": "authenticated",
            "success": "return_nonzero",
        },
        {
            "function": "authorize_request",
            "target": "arg:0",
            "property": "authorized",
            "success": "return_nonzero",
        },
        {
            "function": "verify_signature",
            "target": "arg:0",
            "property": "signature_verified",
            "success": "return_zero",
        },
        {
            "function": "check_version",
            "target": "arg:0",
            "property": "version_checked",
            "success": "return_zero",
        },
        {
            "function": "check_rollback",
            "target": "arg:0",
            "property": "version_checked",
            "success": "return_zero",
        },
        {
            "function": "check_allowlist",
            "target": "arg:0",
            "property": "allowlisted",
            "success": "return_nonzero",
        },
    ],
    "sinks": [
        {
            "function": "flash_write",
            "requirements": {"arg:0": ["bounds_checked", "authorized"]},
        },
        {
            "function": "flash_erase",
            "requirements": {"arg:0": ["bounds_checked", "authorized"]},
        },
        {
            "function": "nvram_write",
            "requirements": {"arg:0": ["bounds_checked", "authorized"]},
        },
        {
            "function": "mmio_write",
            "requirements": {
                "arg:0": ["bounds_checked", "allowlisted"],
                "arg:1": ["authorized"],
            },
        },
        {
            "function": "dma_start",
            "requirements": {"arg:0": ["bounds_checked", "authorized"]},
        },
        {
            "function": "debug_enable",
            "requirements": {"arg:0": ["authenticated", "authorized"]},
        },
        {
            "function": "boot_image_accept",
            "requirements": {
                "arg:0": ["signature_verified", "version_checked"]
            },
        },
        {
            "function": "update_activate",
            "requirements": {
                "arg:0": ["signature_verified", "version_checked", "authorized"]
            },
        },
    ],
}


BUILTIN_SEMANTIC_MODEL_PROFILE_VERSIONS: Mapping[str, int] = {
    EMBEDDED_SECURITY_PROFILE: EMBEDDED_SECURITY_PROFILE_VERSION,
}

_BUILTIN_SEMANTIC_MODEL_PROFILES: Dict[str, Mapping[str, object]] = {
    EMBEDDED_SECURITY_PROFILE: _EMBEDDED_SECURITY_V1,
}


def get_builtin_semantic_model_profile(name: str) -> Mapping[str, object]:
    """Return a defensive copy of a named built-in profile definition."""

    try:
        profile = _BUILTIN_SEMANTIC_MODEL_PROFILES[name]
    except KeyError as exc:
        supported = ", ".join(sorted(_BUILTIN_SEMANTIC_MODEL_PROFILES))
        raise ValueError(
            f"unknown semantic model profile '{name}'; supported profiles: {supported}"
        ) from exc
    return deepcopy(profile)
