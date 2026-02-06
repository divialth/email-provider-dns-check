# Project Agent Instructions

- Always create/activate the `.venv` Python 3.11+ virtualenv and run `pip install '.[test]'` before development.
- Always use the virtualenv interpreter explicitly (e.g., `.venv/bin/python`, `.venv/bin/pip`) when running commands.
- Previous pytest failure was due to missing interpreter; ensure `python` points to the virtualenv before running commands.
- When updating dependencies in `pyproject.toml`, run `./.venv/bin/python scripts/update_requirements.py` to refresh requirements files.
- Always run formatting (black), coverage (`coverage run -m pytest` + `coverage report -m --fail-under=100`), and the full test suite locally (`pytest`) before handing off changes.
- If tests fail (e.g., pytest not found), fix the environment and rerun; do not skip test execution.
- Always add or update tests for any new or changed behavior; include both success and failure paths where applicable.
- Use full Google-style docstrings (summary + Args/Returns/Raises/Attributes where applicable).
- Keep tests organized by feature area; avoid growing monolithic test files.
- Prefer coverage for all output formats and CLI flags when modifying output or CLI behavior.
- Prefer provider-agnostic fixtures in tests (dummy providers) unless validating a real provider config is essential.
- Avoid provider-specific names (e.g., mailbox.org) in tests unless validating real provider configs is required.
- For Jinja2 templates, visually indent output expressions inside control blocks using spaces inside `{{ ... }}` so nesting is obvious without changing rendered output.
- Ensure `yamllint -c .yamllint src` reports no errors before handoff.
- When editing Markdown tables, align columns so the raw Markdown is readable (consistent column widths with aligned pipes).
- For Markdown-only changes, you may skip formatting/lint/test runs.
- When adding new functionality, keep modules small and focused: use per-feature submodules (for example `checker/records/*`, `output/rows/*`, `provider_config/loader/parse/*`, `cli/*` handlers) and re-export from package `__init__` files to preserve stable imports.
- Test structure policy:
  - Prefer shared fixtures/factories over inline setup; reuse `tests/factories.py`, `tests/cli/conftest.py`, and `tests/provider_config/conftest.py` before adding new local builders.
  - Prefer `pytest.mark.parametrize` for repetitive input/expectation matrices instead of copy-pasted test functions.
  - For negative-path tests, assert the specific error/warning message (or stable substring), not only indirect outcomes like "item not listed" or generic exit codes.
  - Keep test files focused and reasonably small; split by feature/scenario before a file grows beyond ~350 lines.
- Git commit messages must follow Conventional Commits 1.0.0 with a required scope and body:
  `type(scope): short description`
  `long description`
  (Body is required; scope is required. Types should follow Conventional Commits, e.g., `feat`, `fix`, `chore`, `docs`, `refactor`, `test`.)
- Versioning must follow Semantic Versioning 2.0.0.
