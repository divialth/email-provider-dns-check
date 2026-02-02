# Email provider custom domain DNS checker

CLI tool to verify that a domain's DNS records match a selected email provider's recommended
configuration (MX, SPF, DKIM, DMARC). Provider rules are stored as YAML files, so adding a new
provider is as easy as dropping in another config file. All output formats include the validated
domain, provider name, provider version, and a report timestamp (UTC).

## Features
- Supports multiple providers via YAML config files
- Validates only the record types present in the provider config
- Strict mode for exact matches; standard mode warns when extras are present
- Configurable DMARC policy/RUA/RUF destinations and SPF policy/includes/IP entries
- Human, text, and JSON output; logging with UTC timestamps
- Tested with Python 3.11+; formatted with `black`

## Dependencies
- Runtime: `dnspython`, `PyYAML`, `Jinja2`
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

### Install directly from the Git repo with pip
Alternate install directly from the Git repo:
```bash
pip install --user "git+https://github.com/divialth/email-provider-dns-check.git"
# optional pin:
pip install --user "git+https://github.com/divialth/email-provider-dns-check.git@v0.2.0"
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
./provider-dns-check example.com --provider dummy_provider
```
The wrapper uses `python3` from your `PATH`, so ensure the runtime dependencies are already
installed in that environment.

## Usage
```bash
provider-dns-check --providers-list
provider-dns-check example.com --provider dummy_provider
provider-dns-check example.com --provider dummy_provider --output json
provider-dns-check example.com --provider dummy_provider --strict
provider-dns-check example.com --provider-detect
provider-dns-check example.com --provider-autoselect
provider-dns-check example.com --provider dummy_provider --dmarc-policy quarantine --dmarc-rua-mailto security@example.com
provider-dns-check example.com --provider dummy_provider --spf-policy softfail --spf-include spf.protection.example
provider-dns-check example.com --provider dummy_provider --txt-verification _verify=token
provider-dns-check --provider-show mailbox.org
```

### Exit codes
- `0` OK
- `1` WARNING
- `2` CRITICAL
- `3` UNKNOWN
These are compatible with Nagios/Icinga plugin exit codes.

### Options (summary)
- `--provider PROVIDER`: provider configuration to use (required unless `--providers-list`)
- `--provider-detect`: detect the closest matching provider and exit
- `--provider-autoselect`: detect the closest matching provider and run checks
- `--providers-list`: list available provider configs and exit
- `--provider-show PROVIDER`: show provider configuration and exit
- `--provider-var NAME=VALUE`: provider variables (repeatable)
- `--version`: show the tool version and exit
- `--output {text,json,human}`: choose output type (default: human; markdown table)
- `--strict`: require exact provider configuration
- `--dmarc-rua-mailto URI`: require a DMARC rua mailto URI (repeatable; overrides provider defaults)
- `--dmarc-ruf-mailto URI`: require a DMARC ruf mailto URI (repeatable; overrides provider defaults)
- `--dmarc-policy {none,quarantine,reject}`: DMARC p= (defaults to provider config)
- `--dmarc-subdomain-policy {none,quarantine,reject}`: DMARC sp= (overrides provider defaults)
- `--dmarc-adkim {r,s}`: DMARC adkim= alignment (overrides provider defaults)
- `--dmarc-aspf {r,s}`: DMARC aspf= alignment (overrides provider defaults)
- `--dmarc-pct 0-100`: DMARC pct= enforcement (overrides provider defaults)
- `--spf-policy {softfail,hardfail}`: SPF terminator (~all or -all)
- `--spf-include VALUE`: additional SPF include mechanisms (repeatable)
- `--spf-ip4 VALUE` / `--spf-ip6 VALUE`: additional SPF ip mechanisms
- `--txt NAME=VALUE`: require TXT record values (repeatable)
- `--txt-verification NAME=VALUE`: require TXT verification record values (repeatable)
- `--skip-txt-verification`: skip provider-required TXT verification checks
- `-v` / `-vv`: increase logging verbosity

## Provider configs
Provider definitions are YAML files. Packaged providers live in
`src/provider_check/providers/*.yaml`. Each file must include a version and can define any
subset of MX/SPF/DKIM/TXT/DMARC. For a fully documented example, see
`src/provider_check/providers/example_do_not_use.yaml`.
Use `enabled: false` at the top level to disable a provider (it will not appear in
`--providers-list`). Boolean fields must be YAML booleans, and list fields must be YAML lists;
scalars are treated as invalid.

Add or override providers by dropping files into one of these locations (first match wins if
provider IDs overlap):
- `${XDG_CONFIG_HOME:-$HOME/.config}/provider-dns-check/providers`
- `/etc/provider-dns-check/providers`
- `/usr/local/etc/provider-dns-check/providers`

Drop a `*.yaml` or `*.yml` file into one of these locations and it will appear in
`--providers-list`.
Invalid provider configs are skipped with a warning.

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
    hosts:
      - "{tenant}.mail.protection.outlook.com."
  dkim:
    selectors:
      - selector1
      - selector2
    record_type: cname
    target_template: "{selector}._domainkey.{tenant}.onmicrosoft.com."
```

### MX fields
MX configs can validate hostnames and (optionally) priorities:
- `hosts`: list of required MX hostnames
- `records`: list of `{host, priority}` entries to enforce priorities
- `priorities`: mapping of `host: priority` (alternate form)

### SPF fields
SPF configs can include additional mechanisms and modifiers beyond includes and IP ranges:
- `required_includes`: list of required include values (without the `include:` prefix)
- `strict_record`: exact SPF string to enforce in strict mode
- `required_mechanisms`: list of required SPF mechanism tokens (e.g., `a`, `mx:mail.example`, `exists:%{i}.spf.example`)
- `allowed_mechanisms`: list of additional mechanism tokens allowed in standard mode
- `required_modifiers`: mapping of SPF modifiers that must match exact values (e.g., `redirect`, `exp`)

### DMARC fields
DMARC configs can optionally enforce more than just `p=` and `rua=`/`ruf=`:
- `default_policy`: default policy if `--dmarc-policy` is not provided
- `required_rua`: list of required rua URIs (for providers with fixed aggregate destinations; `{domain}` is supported)
- `required_ruf`: list of required ruf URIs (for providers with fixed forensic destinations; `{domain}` is supported)
- `required_tags`: mapping of additional DMARC tags that must match exact values
- `rua_required`: require a rua tag in DMARC records (default: false)
- `ruf_required`: require a ruf tag in DMARC records (default: false)

### DKIM fields
DKIM configs can validate either CNAME targets or TXT record values:
- `selectors`: list of DKIM selectors to validate
- `record_type`: `cname` (hosted) or `txt` (self-hosted)
- `target_template`: CNAME target template (required when `record_type: cname`)
- `txt_values`: mapping of `selector: value` to enforce when `record_type: txt`

### CNAME fields
CNAME configs validate arbitrary CNAME records:
- `records`: mapping of `name: target` for required CNAME values

### SRV fields
SRV configs validate required SRV records:
- `records`: mapping of `name: [entries...]`
- Each entry requires `priority`, `weight`, `port`, and `target`

### TXT fields
TXT configs let providers require arbitrary validation records:
- `required`: mapping of `name: [values...]` for required TXT values
- `verification_required`: whether a user-supplied TXT verification record is required (warns if missing unless `--skip-txt-verification`)

## Provider detection (rough overview)
- `--provider-detect` inspects DNS and ranks the top 3 matching providers; it does not run checks.
- `--provider-autoselect` runs detection and then validates DNS with the single best match.
- Detection infers provider variables from DNS templates when possible (for example, MX/DKIM/CNAME/SRV targets).
- If no match is found or the top candidates are tied, detection returns `UNKNOWN` (exit code 3).
- JSON output includes a detection payload with candidates and scores; autoselect JSON also embeds the normal report.

## Templates
Text and human outputs are rendered with Jinja2 templates. Packaged templates live in
`src/provider_check/templates/`.

Add or override templates by dropping `text.j2` and/or `human.j2` into one of these locations:
- `~/.config/provider-dns-check/templates/` (or `$XDG_CONFIG_HOME/provider-dns-check/templates/`)
- `/etc/provider-dns-check/templates/`
- `/usr/local/etc/provider-dns-check/templates/`

Template context includes:
- `domain`, `report_time`, `provider_name`, `provider_version`, `provider_label`, `summary`
- `results` (list of dicts with `record_type`, `status`, `message`, `details`, `selectors`)
- `lines` (legacy list of rendered output lines, populated by text output)
- `table_headers`, `format_row` (human output only)
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

## Notes
- Strict mode enforces the exact DNS strings from the provider config (no extras).
- Standard mode requires the provider essentials and warns when extra mechanisms are present.
- DNS lookup failures report as `UNKNOWN`.

## Vibe-coded notice
Some parts of this project were vibe coded. That means not every code path is perfectly intentional or fully reasoned about. If you depend on this tool, review the logic and add tests for your use case.

## License
GPL-3.0-or-later (see `LICENSE`).
