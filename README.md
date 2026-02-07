# Email provider custom domain DNS checker

CLI tool to verify that a domain's DNS records match a selected email provider's configuration
(MX, SPF, DKIM, DMARC, CAA, CNAME, SRV, TXT, A, AAAA). Provider rules are stored as YAML files, so adding a
new provider is as easy as dropping in another config file. All output formats include the
validated domain, provider name, provider version, and a report timestamp (UTC).

## Features
- Supports multiple providers via YAML config files
- Validates only the record types present in the provider config
- Strict mode for exact matches; standard mode warns when extras are present
- Validates A/AAAA address records when configured
- Configurable DMARC policy/RUA/RUF destinations and SPF policy/includes/IP entries
- Optional custom DNS servers for lookups
- Human, text, and JSON output; logging with UTC timestamps
- Tested with Python 3.11+; formatted with `black`

## Quick start
```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
provider-dns-check --providers-list
provider-dns-check --domain example.com --provider dummy_provider
```

## Dependencies
- Runtime: `dnspython`, `PyYAML`, `Jinja2`, `jsonschema`
- Development/test (optional): `pytest`, `coverage`, `black`, `yamllint`
- `requirements.txt` and `requirements-dev.txt` are auto-generated from `pyproject.toml`.

## Installation
Never run `pip install` as root. Use a virtualenv or `--user` instead.

### Install in a virtualenv
```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

For local development/tests, install dev dependencies instead:
```bash
pip install -r requirements-dev.txt
```

### Install directly from the Git repo with pip
```bash
pip install --user "git+https://github.com/divialth/email-provider-dns-check.git"
# optional pin:
pip install --user "git+https://github.com/divialth/email-provider-dns-check.git@v1.1.0"
```

### Run from a checkout without installing
If you already have the dependencies installed and want to run without installing the package,
clone the repo and use the wrapper script from the repo root:
```bash
git clone https://github.com/divialth/email-provider-dns-check.git
cd email-provider-dns-check
```
Then run:
```bash
./provider-dns-check --providers-list
./provider-dns-check --domain example.com --provider dummy_provider
```
The wrapper uses `python3` from your `PATH`, so ensure the runtime dependencies are already
installed in that environment.

## Usage

List providers:
```bash
provider-dns-check --providers-list
provider-dns-check --providers-list --providers-dir ./providers
provider-dns-check --providers-validate --providers-dir ./providers
provider-dns-check --providers-validate --providers-dir ./providers --output json
```

Use JSON output in CI:
```bash
provider-dns-check --providers-validate --providers-dir ./providers --output json | jq -e '.valid'
```

Run checks:
```bash
provider-dns-check --domain example.com --provider dummy_provider
provider-dns-check --domain example.com --provider dummy_provider --strict
```

Change output format:
```bash
provider-dns-check --domain example.com --provider dummy_provider --output json
```

Detect providers:
```bash
provider-dns-check --domain example.com --provider-detect
provider-dns-check --domain example.com --provider-detect --provider-detect-limit 5
provider-dns-check --domain example.com --provider-autoselect
```

Override policies and records:
```bash
provider-dns-check --domain example.com --provider dummy_provider --dmarc-policy quarantine --dmarc-rua-mailto security@example.com
provider-dns-check --domain example.com --provider dummy_provider --spf-policy softfail --spf-include spf.protection.example
provider-dns-check --domain example.com --provider dummy_provider --txt-verification _verify=token
```

Show a provider config:
```bash
provider-dns-check --provider-show mailbox.org
```

## Exit codes

| Code | Meaning  | Notes                                    |
| ---- | -------- | ---------------------------------------- |
| `0`  | OK       | Successful check.                        |
| `1`  | WARNING  | Non-fatal issues detected.               |
| `2`  | CRITICAL | Required records missing or invalid.     |
| `3`  | UNKNOWN  | DNS lookup failed or provider not found. |

These are compatible with Nagios/Icinga plugin exit codes.

### Options

#### Target
```text
DOMAIN                 domain to validate
--domain DOMAIN         domain to validate (alias for positional argument)
```

#### Provider selection
```text
--providers-list         list available provider configs and exit
--providers-validate     validate external/custom provider YAML files against schema and exit
--providers-dir DIR      additional provider config directory (repeatable)
--provider-show PROVIDER show provider configuration and exit
--provider PROVIDER      provider configuration to use (required unless --providers-list/--providers-validate/--provider-show)
--provider-var NAME=VALUE provider variables (repeatable)
--provider-detect        detect the closest matching provider and exit
--provider-autoselect    detect the closest matching provider and run checks
--provider-detect-limit N limit detection candidates (use with --provider-detect or --provider-autoselect)
```

#### Validation
```text
--strict                     require exact provider configuration
```

#### DMARC overrides
```text
--dmarc-rua-mailto URI               require a DMARC rua mailto URI (repeatable; overrides provider defaults)
--dmarc-ruf-mailto URI               require a DMARC ruf mailto URI (repeatable; overrides provider defaults)
--dmarc-policy {none,quarantine,reject}           DMARC p= (defaults to provider config)
--dmarc-subdomain-policy {none,quarantine,reject} DMARC sp= (overrides provider defaults)
--dmarc-adkim {r,s}                  DMARC adkim= alignment (overrides provider defaults)
--dmarc-aspf {r,s}                   DMARC aspf= alignment (overrides provider defaults)
--dmarc-pct 0-100                    DMARC pct= enforcement (overrides provider defaults)
```

#### SPF overrides
```text
--spf-policy {hardfail,softfail,neutral,allow} SPF all-terminator policy (defaults to provider config)
--spf-include VALUE              additional SPF include mechanisms (repeatable)
--spf-ip4 VALUE                  additional SPF ip mechanisms
--spf-ip6 VALUE                  additional SPF ip mechanisms
```

#### TXT overrides
```text
--txt NAME=VALUE              require TXT record values (repeatable)
--txt-verification NAME=VALUE require TXT verification record values (repeatable)
--skip-txt-verification       skip provider-required TXT verification checks
```

#### Output
```text
--output {text,json,human}   choose output type (default: human; markdown table)
--color {auto,always,never}  colorize output (auto respects NO_COLOR)
--no-color                   disable colorized output
```

#### DNS
```text
--dns-server SERVER   DNS server to use for lookups (repeatable; IP or hostname)
--dns-timeout SECONDS per-query DNS timeout in seconds
--dns-lifetime SECONDS total DNS query lifetime in seconds
--dns-tcp             use TCP for DNS lookups
```

#### Logging
```text
-v / -vv  increase logging verbosity
```

#### Misc
```text
--version show the tool version and exit
```

## Provider configs
Provider definitions are YAML files. Packaged providers live in
`src/provider_check/resources/providers/*.yaml`. Each file must include a version and can define any
subset of MX/SPF/DKIM/CNAME/CAA/SRV/TXT/DMARC/A/AAAA. For a fully documented example, see
`src/provider_check/resources/providers/example_do_not_use.yaml`.
Record type definitions use `required`/`optional` (and `settings` where applicable) as shown below.

### Locations
Add or override providers by dropping files into one of these locations (first match wins if
provider IDs overlap):
- `${XDG_CONFIG_HOME:-$HOME/.config}/provider-dns-check/providers`
- `/etc/provider-dns-check/providers`
- `/usr/local/etc/provider-dns-check/providers`

Use `--providers-dir DIR` to add additional lookup locations (repeatable; searched before the
default directories).

Drop a `*.yaml` or `*.yml` file into one of these locations and it will appear in
`--providers-list`. Invalid provider configs are skipped with a warning.

Use `enabled: false` at the top level to disable a provider (it will not appear in
`--providers-list`). Boolean fields must be YAML booleans, and list fields must be YAML lists;
scalars are treated as invalid.

### Provider metadata fields
Provider configs can include optional descriptive metadata:
- `short_description`: single-line summary (keep under 150 characters)
- `long_description`: multi-line description of the provider/configuration

### Provider inheritance
Providers can inherit from other providers using `extends` with a provider ID (or list of IDs).
The final configuration is a deep merge: mappings are merged recursively, and lists/scalars are
overridden by the child. Use `null` to remove an inherited key (for example, to drop DKIM):
```yaml
extends: base_provider
records:
  dkim: null
```
The `enabled` flag is not inherited from base providers. Base configs can be hidden with
`enabled: false` while still being used for inheritance.

### Provider variables
Providers can define variables and then reference them with `{name}` placeholders in record values.
Variables are resolved before validation with `--provider-var name=value`. `{domain}` is always
available and is filled with the target domain. The `selector` placeholder is reserved for DKIM
target templates.

Example:
```yaml
variables:
  tenant:
    required: true
    description: "Tenant-specific prefix from the provider admin console."
records:
  mx:
    required:
      - host: "{tenant}.mail.protection.outlook.com."
  dkim:
    required:
      selectors:
        - selector1
        - selector2
      record_type: cname
      target_template: "{selector}._domainkey.{tenant}.onmicrosoft.com."
```

### MX fields
MX configs validate hostnames and (optionally) priorities:

| Field      | Description                                                                |
| ---------- | -------------------------------------------------------------------------- |
| `required` | List of required `{host, priority}` entries (priority optional).           |
| `optional` | List of optional `{host, priority}` entries (missing entries WARN).        |

### SPF fields
SPF configs can include additional mechanisms and modifiers beyond includes and IP ranges:

| Field                  | Description                                                                              |
| ---------------------- | ---------------------------------------------------------------------------------------- |
| `required.policy`      | Required SPF all-terminator policy: `hardfail` (`-all`), `softfail` (`~all`), `neutral` (`?all`), or `allow` (`+all`). |
| `required.includes`    | List of required include values (without the `include:` prefix).                         |
| `required.mechanisms`  | Required SPF mechanism tokens (e.g., `a`, `mx:mail.example`, `exists:%{i}.spf.example`). |
| `required.modifiers`   | Mapping of SPF modifiers that must match exact values (e.g., `redirect`, `exp`).         |
| `optional.mechanisms`  | Additional mechanism tokens allowed in standard mode.                                    |
| `optional.modifiers`   | Additional modifiers allowed in standard mode.                                           |

### DMARC fields
DMARC configs can optionally enforce more than just `p=` and `rua=`/`ruf=`:

| Field                   | Description                                                             |
| ----------------------- | ----------------------------------------------------------------------- |
| `required.policy`       | Default policy if `--dmarc-policy` is not provided.                     |
| `required.rua`          | Required rua URIs (fixed aggregate destinations; `{domain}` supported). |
| `required.ruf`          | Required ruf URIs (fixed forensic destinations; `{domain}` supported).  |
| `required.tags`         | Mapping of additional DMARC tags that must match exact values.          |
| `optional.rua`          | Optional rua URIs (accepted when present).                              |
| `optional.ruf`          | Optional ruf URIs (accepted when present).                              |
| `settings.rua_required` | Require a rua tag in DMARC records (default: false).                    |
| `settings.ruf_required` | Require a ruf tag in DMARC records (default: false).                    |

### DKIM fields
DKIM configs can validate either CNAME targets or TXT record values:

| Field                      | Description                                                      |
| -------------------------- | ---------------------------------------------------------------- |
| `required.selectors`       | List of DKIM selectors to validate.                              |
| `required.record_type`     | `cname` (hosted) or `txt` (self-hosted).                         |
| `required.target_template` | CNAME target template (required when `record_type: cname`).      |
| `required.txt_values`      | Mapping of `selector: value` to enforce when `record_type: txt`. |

### A fields
A configs validate IPv4 address records:

| Field      | Description                                                                  |
| ---------- | ---------------------------------------------------------------------------- |
| `required` | Mapping of `name: [values...]` for required A values.                        |
| `optional` | Mapping of `name: [values...]` for optional A values (missing entries WARN). |

### AAAA fields
AAAA configs validate IPv6 address records:

| Field      | Description                                                                    |
| ---------- | ------------------------------------------------------------------------------ |
| `required` | Mapping of `name: [values...]` for required AAAA values.                       |
| `optional` | Mapping of `name: [values...]` for optional AAAA values (missing entries WARN). |

### CNAME fields
CNAME configs validate arbitrary CNAME records:

| Field      | Description                                                                   |
| ---------- | ----------------------------------------------------------------------------- |
| `required` | Mapping of `name: target` for required CNAME values.                          |
| `optional` | Mapping of `name: target` for optional CNAME values (missing entries WARN; mismatches FAIL). |

### CAA fields
CAA configs validate CA authorization records:

| Field      | Description                                                                                         |
| ---------- | --------------------------------------------------------------------------------------------------- |
| `required` | Mapping of `name: [entries...]` (each entry requires `flags`, `tag`, `value`).                      |
| `optional` | Mapping of `name: [entries...]` for optional CAA values (missing entries WARN).                    |

### SRV fields
SRV configs validate required SRV records:

| Field      | Description                                                                                    |
| ---------- | ---------------------------------------------------------------------------------------------- |
| `required` | Mapping of `name: [entries...]` (each entry requires `priority`, `weight`, `port`, `target`).  |
| `optional` | Mapping of `name: [entries...]` for optional SRV values (missing entries WARN; mismatches FAIL). |

In non-strict mode, SRV entries with the correct target/port but different priority or weight report as WARN.

### TXT fields
TXT configs let providers require arbitrary validation records:

| Field                             | Description                                                                                                      |
| --------------------------------- | ---------------------------------------------------------------------------------------------------------------- |
| `required`                        | Mapping of `name: [values...]` for required TXT values.                                                          |
| `optional`                        | Mapping of `name: [values...]` for optional TXT values (missing entries WARN).                                  |
| `settings.verification_required`  | Whether a user-supplied TXT verification record is required (warns if missing unless `--skip-txt-verification`). |

## Provider detection
- `--provider-detect` inspects DNS and ranks the top matches; use `--provider-detect-limit` to change the default limit.
- `--provider-autoselect` runs detection and then validates DNS with the single best match.
- Detection infers provider variables from DNS templates when possible (for example, MX/DKIM/CNAME/SRV targets).
- Optional records (from `optional` sections) add a small tie-breaker bonus when present and appear as `*_OPT`
  entries in detection record summaries.
- If no match is found or the top candidates are tied, detection returns `UNKNOWN` (exit code 3).
- JSON output includes a detection payload with candidates and scores; autoselect JSON also embeds the normal report.

Detection score details:
- Required records only contribute to the core score and ratio.
- Each record type has a weight (`MX=5`, `SPF=4`, `DKIM=4`, `CNAME=3`, `SRV=2`, `CAA=1`, `TXT=1`, `DMARC=1`, `A=1`, `AAAA=1`).
- Status scores are `PASS=2`, `WARN=1`, `FAIL=0`, `UNKNOWN=0`.
- Optional records do not increase `max_score`; they add a small `optional_bonus` when present.

Formula (per provider):
```
score = sum(weight(record_type) * status_score(status)) for required results
max_score = sum(weight(record_type) * status_score(PASS)) for required results
score_ratio = score / max_score (or 0 if max_score is 0)
optional_bonus = sum(weight(record_type)) for optional PASS results
```

Ranking order:
1) `score_ratio` (highest wins)
2) `score` (highest wins)
3) `optional_bonus` (highest wins)
4) provider id (stable sort)

If the top two candidates are tied on ratio, score, and optional bonus, detection is `UNKNOWN`.

## Templates
Text and human outputs are rendered with Jinja2 templates. Packaged templates live in
`src/provider_check/resources/templates/`.

Add or override templates by dropping `text.j2` and/or `human.j2` into one of these locations:
- `~/.config/provider-dns-check/templates/` (or `$XDG_CONFIG_HOME/provider-dns-check/templates/`)
- `/etc/provider-dns-check/templates/`
- `/usr/local/etc/provider-dns-check/templates/`

Template context includes:
- `domain`, `report_time`, `provider_name`, `provider_version`, `provider_label`, `summary`
- `results` (list of dicts with `record_type`, `status`, `message`, `details`, `selectors`, `rows`)
- `lines` (legacy list of rendered output lines, populated by text output)
- `table_headers`, `format_row` (human output only)
- `text_headers`, `format_text_row` (text output only)
- `stringify_details` (human output only)
- `build_table_rows`, `build_table_widths`, `build_table_separator` (human output only)

## Development
- Setup:
```bash
python -m venv .venv
source .venv/bin/activate
pip install '.[test]'
./.venv/bin/python scripts/update_requirements.py
```
- Run tests: `./.venv/bin/python -m pytest`
- Run coverage: `./.venv/bin/coverage run -m pytest` then `./.venv/bin/coverage report -m --fail-under=100`
- Format code: `./.venv/bin/black src tests`
- Lint YAML: `./.venv/bin/yamllint -c .yamllint src`
- Docstrings must use full Google style (summary + sections like Args/Returns/Raises/Attributes when applicable).
- Docstrings are required for all classes/functions in `src` (enforced by `tests/test_docstring_coverage.py`).

## Notes
- Strict mode enforces exact provider constraints and rejects extras.
- Standard mode requires the provider essentials and warns when extra mechanisms are present.
- DNS lookup failures report as `UNKNOWN`.

> Some parts of this project were vibe coded. That means not every code path is perfectly intentional or fully reasoned about. If you depend on this tool, review the logic and add tests for your use case.

## License
GPL-3.0-or-later (see `LICENSE`).
