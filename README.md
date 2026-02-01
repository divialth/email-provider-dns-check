# Email provider custom domain DNS checker

CLI tool to verify that a domain's DNS records match a selected email provider's recommended
configuration (MX, SPF, DKIM, DMARC). Provider rules are stored as YAML files, so adding a new
provider is as easy as dropping in another config file. All output formats include the validated
domain, provider name, provider version, and a report timestamp (UTC).

## Features
- Supports multiple providers via YAML config files
- Validates only the record types present in the provider config
- Strict mode for exact matches; standard mode warns when extras are present
- Configurable DMARC policy/RUA address and SPF policy/includes/IP entries
- Human, text, and JSON output; logging with UTC timestamps
- Tested with Python 3.11+; formatted with `black`

## Dependencies
- Runtime: `dnspython`, `PyYAML`, `Jinja2`
- Development/test (optional): `pytest`
- `requirements.txt` and `requirements-dev.txt` are auto-generated from `pyproject.toml`.

## Installation
```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

If you already have the dependencies installed and want to run without installing the package,
use the wrapper script from the repo root:
```bash
./provider-dns-check --list-providers
./provider-dns-check example.com --provider dummy_provider
```
The wrapper uses `python3` from your `PATH`, so ensure the runtime dependencies are already
installed in that environment.

## Usage
```bash
provider-dns-check --list-providers
provider-dns-check example.com --provider dummy_provider
provider-dns-check example.com --provider dummy_provider --output json
provider-dns-check example.com --provider dummy_provider --strict
provider-dns-check example.com --provider dummy_provider --dmarc-policy quarantine --dmarc-email security@example.com
provider-dns-check example.com --provider dummy_provider --spf-policy softfail --spf-include spf.protection.example
provider-dns-check example.com --provider dummy_provider --txt-verification _verify=token
```

### Exit codes
- `0` OK
- `1` WARNING
- `2` CRITICAL
- `3` UNKNOWN

### Options (summary)
- `--provider PROVIDER`: provider configuration to use (required unless `--list-providers`)
- `--list-providers`: list available provider configs and exit
- `--version`: show the tool version and exit
- `--output {text,json,human}`: choose output type (default: human; markdown table)
- `--strict`: require exact provider configuration
- `--dmarc-email EMAIL`: rua mailbox (mailto: is added)
- `--dmarc-policy {none,quarantine,reject}`: DMARC p= (defaults to provider config)
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
`--list-providers`). Boolean fields must be YAML booleans, and list fields must be YAML lists;
scalars are treated as invalid.

Add or override providers by dropping files into one of these locations (first match wins if
provider IDs overlap):
- `${XDG_CONFIG_HOME:-$HOME/.config}/provider-dns-check/providers`
- `/etc/provider-dns-check/providers`
- `/usr/local/etc/provider-dns-check/providers`

Drop a `*.yaml` or `*.yml` file into one of these locations and it will appear in
`--list-providers`.
Invalid provider configs are skipped with a warning.

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
DMARC configs can optionally enforce more than just `p=` and `rua=`:
- `default_policy`: default policy if `--dmarc-policy` is not provided
- `default_rua_localpart`: default rua localpart if `--dmarc-email` is not provided
- `required_rua`: list of required rua URIs (for providers with fixed aggregate destinations)
- `required_tags`: mapping of additional DMARC tags that must match exact values

### DKIM fields
DKIM configs can validate either CNAME targets or TXT record values:
- `selectors`: list of DKIM selectors to validate
- `record_type`: `cname` (hosted) or `txt` (self-hosted)
- `target_template`: CNAME target template (required when `record_type: cname`)
- `txt_values`: mapping of `selector: value` to enforce when `record_type: txt`

### TXT fields
TXT configs let providers require arbitrary validation records:
- `required`: mapping of `name: [values...]` for required TXT values
- `verification_required`: whether a user-supplied TXT verification record is required (warns if missing unless `--skip-txt-verification`)

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
- Format code: `./.venv/bin/black src tests`
- Lint YAML: `./.venv/bin/yamllint -c .yamllint src`

## Notes
- Strict mode enforces the exact DNS strings from the provider config (no extras).
- Standard mode requires the provider essentials and warns when extra mechanisms are present.
- DNS lookup failures report as `UNKNOWN`.

## License
GPL-3.0-or-later (see `LICENSE`).
