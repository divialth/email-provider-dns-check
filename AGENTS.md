# Project Agent Instructions

- Always create/activate the `.venv` Python 3.11+ virtualenv and run `pip install '.[test]'` before development.
- Always use the virtualenv interpreter explicitly (e.g., `.venv/bin/python`, `.venv/bin/pip`) when running commands.
- Previous pytest failure was due to missing interpreter; ensure `python` points to the virtualenv before running commands.
- When updating dependencies in `pyproject.toml`, run `./.venv/bin/python scripts/update_requirements.py` to refresh requirements files.
- Always run formatting (black), coverage (`coverage run -m pytest` + `coverage report -m --fail-under=100`), and the full test suite locally (`pytest`) before handing off changes.
- If tests fail (e.g., pytest not found), fix the environment and rerun; do not skip test execution.
- Always add or update tests for any new or changed behavior; include both success and failure paths where applicable.
- Keep tests organized by feature area; avoid growing monolithic test files.
- Prefer coverage for all output formats and CLI flags when modifying output or CLI behavior.
- Prefer provider-agnostic fixtures in tests (dummy providers) unless validating a real provider config is essential.
- Avoid provider-specific names (e.g., mailbox.org) in tests unless validating real provider configs is required.
- For Jinja2 templates, visually indent output expressions inside control blocks using spaces inside `{{ ... }}` so nesting is obvious without changing rendered output.
- Ensure `yamllint -c .yamllint src` reports no errors before handoff.
