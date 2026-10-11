# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 0.1.x   | :white_check_mark: |
| < 0.1   | :x:                |

Only the latest minor release line receives security fixes.

## Reporting a Vulnerability

Please **do not** open a public GitHub issue for security vulnerabilities.

Instead, email **hello@prathamjain.com** with:

- a description of the vulnerability,
- steps to reproduce it,
- the version you tested against.

You can expect an acknowledgement within 7 days. If the issue is confirmed,
a fix will be released and credited in the release notes (unless you ask to
stay anonymous).

## Scope notes

- This server is **zero-key**: it needs no API keys and performs read-only
  checks against public data sources (website TLS/DNS inspection, CISA KEV
  and EPSS feeds, MITRE ATT&CK data).
- It never asks for or stores credentials. If you see any prompt or log
  asking for a secret, treat it as a bug and report it.
