# Releasing C-GULL

C-GULL keeps one durable release history in `CHANGELOG.md`. GitHub Releases provide the release-specific narrative and generated pull-request list; do not maintain a second release-notes file in the repository.

## Release checklist

1. Choose the next semantic version and update `cgull.__version__`.
2. Move notable changes from `CHANGELOG.md`'s `Unreleased` section into a dated version section. Keep the changelog user-focused: features, behavior changes, fixes, and important compatibility notes; omit routine test/refactor detail unless it affects users.
3. Open the release-preparation PR and require the normal CI matrix to pass. Confirm the package imports and reports the intended version.
4. Merge the preparation PR to `main`.
5. Create a GitHub Release from `main` using tag `vX.Y.Z`. Use GitHub's generated release notes as the PR/change inventory, then add a short hand-written summary only when the release needs migration guidance, compatibility notes, or highlighted features.
6. Publish the GitHub Release. The PyPI workflow verifies that the release tag matches `cgull.__version__`, builds the sdist/wheel, and publishes through trusted publishing.
7. Verify the GitHub Actions publish job and the published PyPI version.

## Versioning guidance

- Patch (`X.Y.Z+1`): compatible bug fixes, precision improvements, documentation, or internal refactors.
- Minor (`X.Y+1.0`): new rules, meaningful new analysis capability, new public configuration/CLI behavior, or other backward-compatible feature work.
- Major (`X+1.0.0`): intentionally incompatible public API, configuration, output-schema, or CLI changes.

## Release artifacts

Keep these in the repository:

- `CHANGELOG.md` — durable user-facing history.
- `docs/releasing.md` — maintainer process.
- `.github/release.yml` — generated GitHub Release categorization.
- `.github/workflows/publish-pypi.yml` — build/publish automation.

Do not commit generated wheels, source distributions, benchmark output created only for a release announcement, or a duplicate `RELEASE_NOTES.md`. Reproducible benchmark evidence that is part of the project's validation contract can remain under `benchmarks/` or `docs/benchmarks/`.
