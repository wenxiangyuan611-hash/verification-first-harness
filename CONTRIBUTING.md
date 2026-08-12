# Contributing

Thank you for helping make agent workflows more reliable. Contributions should
preserve the project's central invariant: no unverified claim may be treated as
a verified artifact.

## Development setup

```bash
python -m venv .venv
python -m pip install --upgrade pip
python -m pip install -e ".[dev]"
```

Run the complete local quality gate before opening a pull request:

```bash
ruff check .
mypy src
pytest
python -m build
```

The test suite must include a regression test for every behavior change. Security
properties should be tested negatively: demonstrate that tampering, missing
evidence, timeouts, and unsupported obligations fail closed.

## Pull requests

- Keep changes focused and explain the trust boundary affected.
- Add or update documentation for public API or protocol changes.
- Update `CHANGELOG.md` under `Unreleased`.
- Do not weaken baseline obligations in order to make a test pass.
- Never commit API keys, signing keys, credentials, or sensitive receipts.

Opening a pull request confirms that your contribution is licensed under the
Apache License 2.0.
