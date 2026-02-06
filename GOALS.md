# Project Goals

## Current Product Scope
- Provide a CLI tool that checks whether a domain matches an email provider DNS configuration.
- Support these record types when present in provider configs: `MX`, `SPF`, `DKIM`, `DMARC`, `TXT`, `CNAME`, `SRV`, `CAA`, `A`, and `AAAA`.
- Support multiple providers via YAML config files and validate only record types present in the selected provider config.
- Support `required` and `optional` sections per record type under `records`.
- Require provider config versioning and allow configs to define any subset of record types.
- Provide provider detection and provider autoselect flows with cached DNS lookups.
- Allow provider config extension via `extends` and variable substitution.
- Allow provider config and template overrides from user/system config directories.
- Support text, JSON, and human output formats, with human output as default.
- Include clear per-record status output, report summaries, and provider/config version metadata in output.
- Expose a stable runner API:
  `run_checks(CheckRequest) -> CheckResult`
  `run_detection(DetectionRequest) -> DetectionResult`

## CLI and UX Goals
- Support domain input via positional argument and `--domain`.
- Support provider selection/listing/showing and custom providers directories.
- Support DMARC overrides (policy, rua/ruf, subdomain policy, alignment, pct).
- Support SPF overrides (policy, includes, `ip4`, `ip6`).
- Support TXT overrides and optional skip of TXT verification checks.
- Support provider variables via CLI flags.
- Support configurable DNS resolver behavior (servers, timeout, lifetime, TCP).
- Provide consistent exit codes for OK, warning, critical, and unknown outcomes.
- Provide readable help text and predictable defaults.

## Engineering Invariants
- Python is the implementation language; Black is the formatter.
- Use full Google-style docstrings and keep docstring coverage enforced by tests.
- Use `argparse` for CLI parsing and `logging` for runtime messages.
- Use UTC timestamps in logs and output metadata.
- Keep code modular with small, focused per-feature packages and stable re-exports.
- Maintain stable public API surface in `provider_check.api`.
- Keep runner request/response dataclasses stable in `provider_check.runner`.
- Centralize record-type metadata/check enablement in `provider_check.record_registry`.
- Centralize status constants and exit-code mapping in `provider_check.status`.

## Quality Goals
- Keep unit tests comprehensive for checker, CLI, detection, provider loading, and output layers.
- Maintain 100% coverage threshold in CI and local validation.
- Keep README usage examples and provider documentation accurate with shipped behavior.
- Preserve compatibility with Python 3.11+.

## Historical Baseline (Already Completed)
- Repository hosting and collaboration on GitHub.
- Project licensing under GPL-3.0-or-later.
- Repository hygiene basics such as `.gitignore`.
