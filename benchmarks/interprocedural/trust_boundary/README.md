# CGULL-047 embedded trust-boundary corpus

This manifest-driven corpus is the quality gate for CGULL-047 and the shared trust-boundary dataflow. It uses the built-in `embedded-security` semantic profile and keeps trust-boundary metrics independent from unrelated rules.

The baseline is intentionally strict: established cases must remain at **8 TP / 0 FP / 4 TN / 0 FN**. New unsupported scenarios may be added as explicit `known_gap` cases only when the manifest records the expected analyzer result, a reason, and a tracking issue. A resolved gap must be removed from `known_gap` and the baseline ratcheted upward; TP/TN expectations must never be weakened merely to make CI pass.

Coverage includes mailbox-to-flash, DMA, firmware update activation, MMIO/register access, and debug enablement; typed validation, multi-property sinks, early-return guards, conditional/loop/switch paths, validation after a sink, and an interprocedural source wrapper. The corpus tests the configured semantic contracts, not vendor-name inference. Unknown or unmodeled HAL calls remain outside the supported boundary until explicitly mapped.

`tests/test_trust_boundary_benchmark.py` validates the manifest and runs each fixture twice to guard deterministic results. Regressions from the recorded baseline fail the normal pytest CI job.
