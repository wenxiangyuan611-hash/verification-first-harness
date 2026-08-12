# Release Process

1. Ensure CI is green on `main`.
2. Move relevant entries from `Unreleased` to the new version in `CHANGELOG.md`.
3. Update the version in `pyproject.toml` and `src/verification_harness/__init__.py`.
4. Run `make check` or the equivalent commands on Windows.
5. Commit the release, create a signed `vX.Y.Z` tag, and push the tag.
6. The release workflow builds wheel/source distributions, installs the wheel,
   runs the demo, and attaches artifacts to a generated GitHub Release.

For the first publication, enable GitHub Issues and private vulnerability
reporting, set `main` as the default branch, and require the `Quality gate` plus
matrix test jobs before merging.
