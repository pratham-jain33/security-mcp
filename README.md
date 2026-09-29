# security-mcp

mcp-name: io.github.pratham-jain33/security-mcp

The zero-key cybersecurity toolkit for your AI assistant. No API keys, no signups, no configuration. Install it, ask Claude a security question, get an answer.

Three tools:

- **audit_site** — grade any website's security from A+ to F. Checks HTTP security headers (HSTS, CSP, X-Frame-Options and more), the SSL/TLS certificate (valid, issuer, days until expiry), and DNS email-auth records (SPF, DMARC, DKIM). Every finding comes with a plain-English explanation.
- **check_cve** — is this vulnerability actively exploited right now, and how likely is it to be exploited soon? Reads CISA's Known Exploited Vulnerabilities catalog and the FIRST EPSS score. Both are free public feeds.
- **lookup_attack** — MITRE ATT&CK techniques in plain English. Give a technique ID like `T1566` or a keyword like `phishing`; get what it is, how attackers use it, how to spot it, and how to defend. The technique data ships with the package, so this works fully offline.

Defensive only. This server audits and explains; it does not scan ports, exploit anything, or do anything offensive.

## Install

Requires Python 3.10+.

```bash
uvx security-mcp
```

Or with pip:

```bash
pip install security-mcp
```

Claude Desktop config:

```json
{
  "mcpServers": {
    "shield": {
      "command": "uvx",
      "args": ["security-mcp"]
    }
  }
}
```

## Try it

- "Audit the security of example.com"
- "Is CVE-2021-44228 being exploited right now?"
- "What is T1566 and how do I defend against it?"

## How it works

`audit_site` fetches the site's homepage over HTTPS and reads its response headers, opens a TLS connection to inspect the certificate dates and issuer, and looks up SPF/DMARC/DKIM records over DNS (falling back to DNS-over-HTTPS where direct DNS is blocked). Each check carries a penalty; the penalties add up to a score, and the score maps to a grade. A failed certificate check fails the whole audit.

`check_cve` validates the CVE ID format, then asks two free public sources: the CISA KEV catalog (a JSON feed of vulnerabilities confirmed to be exploited in the wild, cached in memory for an hour) and the FIRST EPSS API (a 0–100% probability of exploitation in the next 30 days). The verdict combines both.

`lookup_attack` searches a compact bundle of the public MITRE ATT&CK catalog (697 techniques, trimmed from MITRE's CTI feed and shipped inside the package). ID lookups are exact; keyword searches rank name matches above description matches.

## Development

```bash
python -m venv .venv
.venv/bin/pip install -e . pytest
.venv/bin/python -m pytest tests/ -q            # unit tests (mocked network)
SHIELD_LIVE=1 .venv/bin/python -m pytest tests/ -q -k live  # real network smoke tests
```

## License

MIT
