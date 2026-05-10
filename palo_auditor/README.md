# Palo Alto Firewall Policy Auditor

Export and audit Palo Alto firewall security policies. Produces a JSON
audit report, a Markdown summary, and preserves the raw policy export for
traceability.

Built for CCDC inject TOOL26T ("Export Firewall Security Policy for
Auditors") and similar internal/external audit prep tasks.

## Features

- Two transports: Palo Alto XML API (preferred) or SSH/CLI fallback
- Offline mode: re-audit a previously saved policy export without
  reconnecting to the firewall
- Audit checks:
  - **overly_permissive** — flags `any/any/allow` rules
  - **missing_logging** — flags allow-rules with no logging configured
  - **risky_services** — flags rules permitting cleartext/legacy
    protocols (telnet, ftp, etc.)
  - **disabled_rules** — flags disabled rules left in the policy
- Output formats: JSON (machine-readable) and Markdown (human-readable)
- Credentials read from environment variables, never stored in config
  files
- Findings sorted high → medium → low severity for fast triage

## Requirements

- Python 3.10+
- See `requirements.txt`

## Installation

```bash
git clone <repo-url> palo-auditor
cd palo-auditor
python -m venv .venv
source .venv/bin/activate          # on Windows: .venv\Scripts\activate
pip install -r requirements.txt
```

## Usage

### Offline mode (no firewall needed — great for dev/demo)

```bash
python -m src.main \
    --config data/samples/audit_config_offline.json \
    --output reports/sample_audit.json
```

### Live mode against a real firewall

1. Generate a Palo Alto XML API key. Most Palo Alto firewalls accept this
   request to mint one (replace placeholders):

   ```bash
   curl -k "https://<firewall-host>/api/?type=keygen&user=<user>&password=<password>"
   ```

   The response contains `<key>...</key>`. Copy that value.

2. Export it as an environment variable:

   ```bash
   export PALO_API_KEY='<the-key-from-step-1>'
   ```

3. Edit `data/samples/audit_config_live.json` to set `target.host` and any
   policy preferences. Then run:

   ```bash
   python -m src.main \
       --config data/samples/audit_config_live.json \
       --output reports/audit_$(date +%Y%m%d).json \
       --verbose
   ```

### Validate a config without connecting

```bash
python -m src.main --config <path> --dry-run
```

### Re-audit a previously saved export

```bash
python -m src.main \
    --config <path> \
    --offline reports/raw_policy.xml \
    --output reports/reaudit.json
```

## CLI reference

| Flag             | Description                                              |
|------------------|----------------------------------------------------------|
| `--config PATH`  | Audit config JSON (required)                             |
| `--output PATH`  | JSON report path (default: `reports/audit_report.json`)  |
| `--summary PATH` | Markdown summary path (default: alongside JSON)          |
| `--raw-export PATH` | Where to save the unmodified policy export            |
| `--offline PATH` | Force file mode using this saved export                  |
| `--include-rules` | Embed all parsed rules in the JSON report               |
| `--dry-run`      | Validate config and exit without connecting              |
| `--verbose`      | Enable DEBUG-level logging                               |

## Running tests

```bash
pip install -r requirements.txt
pytest -v
```

The test suite covers the parser, each audit check, config validation,
and a full end-to-end integration run against the bundled sample policy.

## Project structure

```
palo_auditor/
├── src/
│   ├── main.py            # CLI entry point
│   ├── config.py          # JSON config load + validation + env var resolution
│   ├── firewall_client.py # XML API and SSH transports
│   ├── parser.py          # XML → PolicyRule
│   ├── policy_rule.py     # PolicyRule dataclass
│   ├── auditor.py         # PolicyAuditor with check_* methods
│   └── report.py          # AuditReport — JSON + Markdown writers
├── tests/
│   ├── test_parser.py
│   ├── test_auditor.py
│   ├── test_config.py
│   └── test_integration.py
├── data/samples/          # Sample policy XML and configs
├── reports/               # Output directory (gitignored)
└── requirements.txt
```

## Security notes

- **Credentials are never stored in config files.** The config names an
  environment variable; the value is read at runtime. Don't bypass this.
- **TLS verification is off by default** because Palo Alto management
  interfaces typically have self-signed certs. For production use, set
  `target.verify_tls: true` and trust the cert properly.
- **SSH host key verification.** When SSH mode is used without a
  `known_hosts_file` configured, the tool auto-accepts any host key. This
  is convenient for lab work but vulnerable to MitM. Configure
  `known_hosts_file` for any non-lab use.
- **The raw policy export is sensitive.** Treat `reports/raw_policy.xml`
  the same way you'd treat any firewall config dump.

## Exit codes

| Code | Meaning                                          |
|------|--------------------------------------------------|
| 0    | Success                                          |
| 2    | Config error (missing/invalid config)            |
| 3    | Firewall error (connection, auth, transport)     |
| 4    | Parse error (malformed policy data)              |
| 10   | Unexpected error                                 |
| 130  | Interrupted (Ctrl-C)                             |
