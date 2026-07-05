## CertSnipe

Monitors certificate transparency logs for AitM phishing infrastructure. Tracks both the well-known Duo-SSO-hijacking pattern (evilginx-style `api-<duoid>.` subdomains) and keyword-based identification for organizations that may not use Duo, or may only use it for some users. Uses a local [`certstream-server-go`](https://github.com/d-Rickyy-b/certstream-server-go) instance (via Docker) as the CT data source.

| File | Purpose |
|------|---------|
| `targets.json` | Targeted organizations (Duo ID or keyword → name + email). Must be manually populated. |
| `.env.example` | Template for required environment variables. Copy to `.env` before running. |
| `email_template.example.txt` | Example email template. Copy to `email_template.txt` to customize. |
| `known_domains.txt` | Known attacker domains, so new certs on these are flagged high-confidence. |
| `known_ips.txt` | Known attacker IPs, so low-confidence matches resolving here are upgraded. |
| `watched_org_ids.txt` | Optional. Org IDs (one per line) whose alerts are also sent to `DISCORD_WEBHOOK_WATCHED`. |

`targets.json` supports two entry formats:

**Duo target** (original format — entries with no `"type"` field):
```json
{
  "<duo id>": {
    "name": "<university name>",
    "email": "<university email>"
  }
}
```

**Keyword target** (for organizations that may not use Duo, or may only use it for some users):
```json
{
  "<keyword id>": {
    "type": "keyword",
    "name": "<university name>",
    "email": "<university email>",
    "keywords": ["<keyword1>", "<keyword2>"]
  }
}
```
- `type` must be `"keyword"` (Duo entries don't need this field — backwards compatible).
- `keywords` is a list of strings to match as substrings within subdomain parts (case-insensitive). If omitted, the JSON key itself is used as the keyword.

## Usage
1. Clone the repository and navigate to the project directory.
2. Create a `.env` file based on the `.env.example` and fill in the required environment variables.
   - `CERTSTREAM_WS_URL` - WebSocket URL of your certstream server. With the included Docker setup on the same machine: `ws://127.0.0.1:8080/`
3. ```docker-compose up -d``` to start the certstream server.
4. (Optional) Create and activate a virtual environment:
   ```bash
   python3 -m venv .venv
   source .venv/bin/activate
   ```
5. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```
6. Run the watcher script:
   ```bash
   python watcher.py
   ```

### Without Docker
If you prefer to run certstream-server-go as a standalone binary instead of Docker:
1. Download the release binary from [certstream-server-go releases](https://github.com/d-Rickyy-b/certstream-server-go/releases).
2. Run it with the included config: `./certstream-server-go -config config.yaml`

The `CERTSTREAM_WS_URL` is the same either way: `ws://127.0.0.1:8080/`

## Email Template

The email template controls the body of both automated SMTP emails and the
mailto links embedded in Discord alerts.

1. Copy the example and customize:
   ```bash
   cp email_template.example.txt email_template.txt
   ```

2. The `{IOCS_LIST}` placeholder is required — it gets replaced at runtime
   with defanged domains (up to 50) and non-CDN IPs (up to 20).

3. (Optional) Set `AUTOMATED_EMAIL_DISCLAIMER` in your `.env` to append a
   footer to every automated SMTP email. A default disclaimer is used if
   not set.

## Testing

### Unit tests
```bash
python -m pytest tests/ -v
```

### Integration tests (optional)
These send real alerts to verify delivery. Skipped in CI by default.

```bash
# Set your test webhook/Apprise URLs
export TEST_DISCORD_WEBHOOK="https://discord.com/api/webhooks/..."
export TEST_APPRISE_URL="discord://webhook_id/webhook_token"

# Run integration tests
python -m pytest tests/test_integration_alerts.py -v
```

Apprise supports 80+ notification services. See [Apprise docs](https://github.com/caronc/apprise#supported-notifications) for URL formats.
