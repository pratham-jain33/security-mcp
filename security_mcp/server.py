"""security-mcp: a zero-key cybersecurity toolkit for any AI assistant.

Three tools, no API keys, no signups, nothing to configure:

- audit_site: grade any website's security (headers, SSL certificate,
  email-auth records) from A+ to F, with plain-English findings.
- check_cve: is this vulnerability actively exploited right now, and how
  likely is it to be exploited soon? (CISA KEV + FIRST EPSS, both free.)
- lookup_attack: MITRE ATT&CK techniques explained in plain English.

Everything here is defensive: audits and lookups only. There is no port
scanning, no exploit code, nothing offensive.
"""

import json
import os
import re
import socket
import ssl
import time
from base64 import b64encode
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse

import dns.resolver
import requests
from fastmcp import FastMCP


# ---------------------------------------------------------------------------
# The waiter is born. This names our server. The name is what shows up
# in the assistant's list of connected tools.
# ---------------------------------------------------------------------------
mcp = FastMCP("security-mcp")


# ---------------------------------------------------------------------------
# Shared helpers: small utilities every tool reuses.
# ---------------------------------------------------------------------------

# A hostname is letters, digits, hyphens and dots. This keeps out URLs
# pasted with paths, ports, or anything sneaky.
_HOSTNAME_RE = re.compile(r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))*$")

# How long we wait for any single network answer before giving up.
NETWORK_TIMEOUT = 15


def _clean_domain(raw: str) -> str | None:
    """Turn whatever the user typed into a bare domain name.

    Accepts "example.com", "https://example.com/path", "EXAMPLE.COM ".
    Returns None if it doesn't look like a real hostname.
    """
    text = (raw or "").strip().lower()
    # Strip a scheme ("https://") if one was pasted.
    text = re.sub(r"^https?://", "", text)
    # Drop everything after the first slash, question mark, or hash.
    text = re.split(r"[/?#]", text, maxsplit=1)[0]
    # Drop a port (":8080") if present.
    text = text.split(":")[0]
    # Drop a trailing dot ("example.com." is legal DNS, but ugly).
    text = text.rstrip(".")
    if not text or not _HOSTNAME_RE.match(text):
        return None
    return text


def _plain_error(what: str) -> str:
    """One consistent shape for 'the internet didn't cooperate' messages."""
    return (
        f"Could not check {what}: the network request failed or timed out. "
        "Check the domain is correct and your internet connection works, "
        "then try again."
    )


def _https_proxy_url() -> str | None:
    """The configured HTTPS proxy, if any (corporate networks, sandboxes).

    Read from the standard environment variables. Returns None on a
    normal direct connection.
    """
    for var in ("HTTPS_PROXY", "https_proxy"):
        value = os.environ.get(var, "").strip()
        if value:
            return value
    return None


def _connect_tls(domain: str):
    """Open a TLS connection to domain:443 and return the wrapped socket.

    Goes straight there normally; tunnels through the HTTPS proxy with an
    HTTP CONNECT request when one is configured. The caller uses it as a
    context manager (``with`` block).
    """
    context = ssl.create_default_context()
    proxy = _https_proxy_url()
    if not proxy:
        sock = socket.create_connection((domain, 443), timeout=NETWORK_TIMEOUT)
        return context.wrap_socket(sock, server_hostname=domain)

    parts = urlparse(proxy)
    sock = socket.create_connection(
        (parts.hostname, parts.port or 3128), timeout=NETWORK_TIMEOUT
    )
    request = f"CONNECT {domain}:443 HTTP/1.1\r\nHost: {domain}:443\r\n"
    if parts.username:
        # Proxy credentials come from the environment; they are only used
        # here for this one connection, never printed or stored.
        creds = b64encode(
            f"{parts.username}:{parts.password or ''}".encode()
        ).decode()
        request += f"Proxy-Authorization: Basic {creds}\r\n"
    request += "\r\n"
    sock.sendall(request.encode())
    response = b""
    while b"\r\n\r\n" not in response:
        chunk = sock.recv(4096)
        if not chunk:
            break
        response += chunk
    status_line = response.split(b"\r\n", 1)[0]
    if b" 200" not in status_line:
        sock.close()
        raise OSError("the configured proxy refused the secure connection")
    return context.wrap_socket(sock, server_hostname=domain)


# ===========================================================================
# TOOL 1: audit_site
# ===========================================================================
# A website security audit in three parts:
#   1. HTTP security headers: notes the server attaches to every visitor.
#   2. The SSL certificate: the site's ID card (valid? expiring soon?).
#   3. Email-auth DNS records: can attackers send fake email as this domain?
# Each part returns findings; _grade_site turns them into an A+..F grade.
# ===========================================================================

# Every header we grade: what good looks like, what it costs when missing,
# and the one-line plain-English explanation shown to the user.
HEADER_CHECKS = [
    {
        "header": "strict-transport-security",
        "label": "HSTS",
        "penalty": 15,
        "explain": (
            "Tells browsers to only ever use encrypted HTTPS for this site, "
            "never plain HTTP. Without it, attackers on the same network can "
            "downgrade visitors to unencrypted connections."
        ),
        "check": lambda v: v is not None and "max-age=" in v.lower(),
        "weak_hint": (
            "HSTS is present but has no max-age directive, so browsers may "
            "ignore it. It should look like: max-age=31536000."
        ),
    },
    {
        "header": "content-security-policy",
        "label": "CSP",
        "penalty": 15,
        "explain": (
            "An allowlist of where the page may load scripts and content from. "
            "Without it, one injected script can take over the whole page."
        ),
        "check": lambda v: v is not None and len(v.strip()) > 0,
        "weak_hint": "",
    },
    {
        "header": "x-frame-options",
        "label": "X-Frame-Options",
        "penalty": 10,
        "explain": (
            "Stops other sites from embedding this site invisibly inside theirs. "
            "Without it, attackers can overlay invisible frames to hijack clicks "
            "(clickjacking)."
        ),
        # frame-ancestors inside CSP does the same job, so that counts too.
        "check": lambda v, headers: (
            v is not None
            or "frame-ancestors" in headers.get("content-security-policy", "").lower()
        ),
        "weak_hint": "",
    },
    {
        "header": "x-content-type-options",
        "label": "X-Content-Type-Options",
        "penalty": 5,
        "explain": (
            "Stops browsers from guessing file types. Without 'nosniff', a "
            "browser can be tricked into running an uploaded file as code."
        ),
        "check": lambda v: v is not None and v.strip().lower() == "nosniff",
        "weak_hint": (
            "Present but not set to 'nosniff', so it does nothing. "
            "It should be exactly: nosniff."
        ),
    },
    {
        "header": "referrer-policy",
        "label": "Referrer-Policy",
        "penalty": 5,
        "explain": (
            "Controls how much of the page address leaks to other sites when "
            "visitors click links. Without it, private URLs can leak out."
        ),
        "check": lambda v: v is not None and len(v.strip()) > 0,
        "weak_hint": "",
    },
    {
        "header": "permissions-policy",
        "label": "Permissions-Policy",
        "penalty": 5,
        "explain": (
            "Decides which browser features (camera, microphone, location) the "
            "page may use. Without it, any script on the page can request them."
        ),
        "check": lambda v: v is not None and len(v.strip()) > 0,
        "weak_hint": "",
    },
]


def _fetch_headers(domain: str):
    """Download the site's homepage and return its response headers.

    Returns (headers_dict, final_url, error_message). Only one of the last
    two is ever set: either we got headers, or we got an error message.
    """
    url = f"https://{domain}/"
    try:
        resp = requests.get(
            url,
            timeout=NETWORK_TIMEOUT,
            headers={"User-Agent": "security-mcp/0.1 (security audit)"},
            allow_redirects=True,
        )
    except requests.RequestException:
        return None, None, _plain_error(f"https://{domain}")
    # requests lowercases nothing; HTTP headers are case-insensitive, so we
    # normalize to lowercase once and forget about casing forever.
    headers = {k.lower(): v for k, v in resp.headers.items()}
    return headers, resp.url, None


def _check_ssl(domain: str) -> dict:
    """Inspect the site's SSL certificate: valid? expiring? by whom?

    Returns a dict with keys: ok, detail (plain English), days_left,
    issuer, penalty, critical. 'critical' means 'fail the whole audit'.
    """
    result = {
        "ok": False,
        "detail": "",
        "days_left": None,
        "issuer": "",
        "penalty": 0,
        "critical": False,
    }
    try:
        with _connect_tls(domain) as tls:
            cert = tls.getpeercert()
    except (socket.error, ssl.SSLError, OSError):
        result["detail"] = (
            "Could not establish a trusted HTTPS connection: no valid "
            "certificate was presented. Visitors would see a browser warning."
        )
        result["penalty"] = 60
        result["critical"] = True
        return result

    # The certificate dates look like "Sep 29 12:00:00 2026 GMT".
    not_after = cert.get("notAfter", "")
    try:
        expiry = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z").replace(
            tzinfo=timezone.utc
        )
    except ValueError:
        result["detail"] = "Got a certificate but could not read its expiry date."
        result["penalty"] = 20
        return result

    days_left = (expiry - datetime.now(timezone.utc)).days
    result["days_left"] = days_left
    issuer = dict(x[0] for x in cert.get("issuer", ()))
    result["issuer"] = issuer.get("organizationName", "unknown issuer")

    if days_left < 0:
        result["detail"] = (
            f"The certificate EXPIRED {-days_left} days ago. Browsers show "
            "visitors a full-page warning on this site right now."
        )
        result["penalty"] = 60
        result["critical"] = True
    elif days_left < 14:
        result["detail"] = (
            f"The certificate expires in {days_left} days (issued by "
            f"{result['issuer']}). Renew it this week or visitors will start "
            "seeing browser warnings."
        )
        result["penalty"] = 15
        result["ok"] = True
    elif days_left < 30:
        result["detail"] = (
            f"The certificate is valid but expires in {days_left} days "
            f"(issued by {result['issuer']}). Put renewal on the calendar."
        )
        result["penalty"] = 5
        result["ok"] = True
    else:
        result["detail"] = (
            f"Certificate is valid for {days_left} more days "
            f"(issued by {result['issuer']})."
        )
        result["ok"] = True
    return result


# DKIM works with "selectors": short names the domain owner picks. We can't
# ask the domain which selectors it uses, so we probe the common ones.
# Finding any is a pass; finding none is "probably not set up".
COMMON_DKIM_SELECTORS = [
    "default",
    "google",
    "selector1",
    "selector2",
    "k1",
    "k2",
    "mail",
    "email",
    "dkim",
    "s1",
    "s2",
]


def _txt_records_doh(name: str) -> list:
    """DNS TXT lookup over HTTPS (free public resolvers, no key).

    Used when direct DNS on port 53 is blocked (some sandboxes, strict
    firewalls). Tries Google's resolver, then Cloudflare's.
    """
    for url in ("https://dns.google/resolve", "https://cloudflare-dns.com/dns-query"):
        try:
            resp = requests.get(
                url,
                params={"name": name, "type": "TXT"},
                headers={"Accept": "application/dns-json"},
                timeout=NETWORK_TIMEOUT,
            )
            data = resp.json()
        except (requests.RequestException, ValueError):
            continue
        records = []
        for answer in data.get("Answer", []):
            if answer.get("type") == 16:  # 16 = TXT record
                raw = str(answer.get("data", ""))
                # Google returns chunks quoted ("v=spf1" "more"), Cloudflare
                # too, but some answers come back unquoted: handle both.
                chunks = re.findall(r'"([^"]*)"', raw)
                text = "".join(chunks) if chunks else raw.strip('"')
                if text:
                    records.append(text)
        # Status 0 means "asked and answered" (even if the answer is empty).
        if records or data.get("Status") == 0:
            return records
    return []


def _txt_records(name: str) -> list:
    """Fetch TXT records for a DNS name. Empty list = none found or DNS failed."""
    try:
        resolver = dns.resolver.Resolver()
        resolver.lifetime = 10
        answers = resolver.resolve(name, "TXT")
        return ["".join(r.decode() if isinstance(r, bytes) else str(r) for r in rr.strings) for rr in answers]
    except Exception:
        # Direct DNS failed (NXDOMAIN, timeout, blocked port 53):
        # try DNS-over-HTTPS before giving up.
        return _txt_records_doh(name)


def _check_email_auth(domain: str) -> list:
    """Check SPF, DMARC, and DKIM. Returns a list of finding dicts.

    Each finding: label, status ("pass"/"warn"/"fail"), detail, penalty.
    """
    findings = []

    # -- SPF: a TXT record at the bare domain starting with "v=spf1". --
    spf_records = [r for r in _txt_records(domain) if r.lower().startswith("v=spf1")]
    if spf_records:
        rec = spf_records[0]
        if "+all" in rec or " ?all" in rec or rec.strip().endswith("?all"):
            findings.append({
                "label": "SPF", "status": "warn", "penalty": 5,
                "detail": (
                    "SPF exists but ends in '?all', which means 'no opinion' "
                    "about servers not on the list. Attackers' servers are "
                    "not rejected. It should end in '-all' (hard fail)."
                ),
            })
        else:
            findings.append({
                "label": "SPF", "status": "pass", "penalty": 0,
                "detail": "SPF record found: lists which mail servers may send as this domain.",
            })
    else:
        findings.append({
            "label": "SPF", "status": "fail", "penalty": 10,
            "detail": (
                "No SPF record. Anyone on the internet can send email that "
                "claims to be from this domain."
            ),
        })

    # -- DMARC: a TXT record at _dmarc.<domain> starting with "v=DMARC1". --
    dmarc_records = [r for r in _txt_records(f"_dmarc.{domain}") if "v=dmarc1" in r.lower()]
    if dmarc_records:
        rec = dmarc_records[0].lower()
        policy = re.search(r"p=(\w+)", rec)
        pol = policy.group(1) if policy else "?"
        if pol == "none":
            findings.append({
                "label": "DMARC", "status": "warn", "penalty": 3,
                "detail": (
                    "DMARC exists but the policy is 'p=none': it only watches "
                    "and reports, it rejects nothing. Move to 'quarantine' or "
                    "'reject' to actually block fakes."
                ),
            })
        else:
            findings.append({
                "label": "DMARC", "status": "pass", "penalty": 0,
                "detail": f"DMARC policy is 'p={pol}': failing mail gets {pol}d.",
            })
    else:
        findings.append({
            "label": "DMARC", "status": "fail", "penalty": 10,
            "detail": (
                "No DMARC record. Even with SPF/DKIM, receivers don't know "
                "what to do with mail that fails the checks."
            ),
        })

    # -- DKIM: probe common selectors at <selector>._domainkey.<domain>. --
    found_selectors = []
    for selector in COMMON_DKIM_SELECTORS:
        records = _txt_records(f"{selector}._domainkey.{domain}")
        if any("v=dkim1" in r.lower() or "k=rsa" in r.lower() or "p=" in r.lower() for r in records):
            found_selectors.append(selector)
    if found_selectors:
        findings.append({
            "label": "DKIM", "status": "pass", "penalty": 0,
            "detail": f"DKIM signing key published (selector '{found_selectors[0]}'): outgoing mail is cryptographically signed.",
        })
    else:
        findings.append({
            "label": "DKIM", "status": "warn", "penalty": 5,
            "detail": (
                "No DKIM key found under common selectors. Mail from this "
                "domain is probably not cryptographically signed."
            ),
        })

    return findings


def _score_to_grade(score: int, critical: bool) -> str:
    """Turn a 0-100 score into a letter grade. Critical failures cap at F."""
    if critical or score < 55:
        return "F"
    if score >= 95:
        return "A+"
    if score >= 90:
        return "A"
    if score >= 80:
        return "B"
    if score >= 70:
        return "C"
    return "D"


def _grade_site(header_findings: list, ssl_result: dict, email_findings: list) -> tuple:
    """Add up penalties and return (grade, score, critical). Pure logic: no network."""
    score = 100
    critical = ssl_result.get("critical", False)
    for f in header_findings:
        score -= f["penalty"]
    score -= ssl_result.get("penalty", 0)
    for f in email_findings:
        score -= f["penalty"]
    score = max(0, score)
    return _score_to_grade(score, critical), score, critical


@mcp.tool()
def audit_site(domain: str) -> str:
    """Audits a website's security posture and returns a grade from A+ to F. Checks HTTP security headers (HSTS, CSP, X-Frame-Options and more), the SSL/TLS certificate (valid, issuer, days until expiry), and DNS email-auth records (SPF, DMARC, DKIM). Every finding comes with a plain-English explanation. Use when the user asks how secure a site is, or wants a quick security review of their own website. Takes a domain like "example.com". Defensive audit only: makes normal HTTPS and DNS requests, no scanning or probing beyond that."""
    clean = _clean_domain(domain)
    if not clean:
        return (
            f"'{domain}' doesn't look like a valid domain name. "
            "Pass a bare domain like \"example.com\"."
        )

    # -- Part 1: fetch the homepage and grade its security headers. --
    headers, final_url, fetch_error = _fetch_headers(clean)
    header_findings = []
    if fetch_error:
        # If HTTPS itself failed, the SSL check below will explain why.
        # Headers get maximum penalty: we couldn't even read them.
        for spec in HEADER_CHECKS:
            header_findings.append({
                "label": spec["label"], "status": "fail",
                "penalty": spec["penalty"],
                "detail": f"Could not check: the site didn't load over HTTPS. {spec['explain']}",
            })
    else:
        for spec in HEADER_CHECKS:
            value = headers.get(spec["header"])
            checker = spec["check"]
            try:
                # Some checks need the other headers too (X-Frame-Options
                # accepts frame-ancestors in CSP as equivalent).
                passed = checker(value, headers)
            except TypeError:
                passed = checker(value)
            if passed:
                header_findings.append({
                    "label": spec["label"], "status": "pass",
                    "penalty": 0, "detail": "Present and correctly set.",
                })
            elif value:
                header_findings.append({
                    "label": spec["label"], "status": "warn",
                    "penalty": spec["penalty"] // 2,
                    "detail": spec["weak_hint"] or spec["explain"],
                })
            else:
                header_findings.append({
                    "label": spec["label"], "status": "fail",
                    "penalty": spec["penalty"], "detail": spec["explain"],
                })

    # -- Part 2: the SSL certificate. --
    ssl_result = _check_ssl(clean)

    # -- Part 3: email-auth DNS records. --
    email_findings = _check_email_auth(clean)

    grade, score, _ = _grade_site(header_findings, ssl_result, email_findings)

    # -- Assemble the report in plain text. --
    lines = [f"Security audit for {clean} — Grade: {grade} (score {score}/100)", ""]
    if final_url and final_url != f"https://{clean}/":
        lines.append(f"Note: the site redirected to {final_url}")
        lines.append("")

    lines.append("HTTP security headers:")
    for f in header_findings:
        mark = {"pass": "[+]", "warn": "[!]", "fail": "[-]"}[f["status"]]
        lines.append(f"  {mark} {f['label']}: {f['detail']}")
    lines.append("")

    lines.append("SSL certificate:")
    mark = "[+]" if ssl_result["ok"] else "[-]"
    lines.append(f"  {mark} {ssl_result['detail']}")
    lines.append("")

    lines.append("Email authentication (DNS):")
    for f in email_findings:
        mark = {"pass": "[+]", "warn": "[!]", "fail": "[-]"}[f["status"]]
        lines.append(f"  {mark} {f['label']}: {f['detail']}")

    return "\n".join(lines)


# ===========================================================================
# TOOL 2: check_cve
# ===========================================================================
# Answers two questions about a vulnerability ID like CVE-2021-44228:
#   1. Is it being actively exploited RIGHT NOW? (CISA's KEV catalog)
#   2. How likely is it to be exploited SOON? (FIRST's EPSS score)
# Both sources are free public feeds that need no key and no signup.
# ===========================================================================

# CVE IDs look like CVE-2021-44228: "CVE-", a 4-digit year, then 4+ digits.
CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE)

# The official CISA feed. This URL is published on cisa.gov's KEV page.
KEV_FEED_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
# FIRST's Exploit Prediction Scoring System API. Free, no key.
EPSS_API_URL = "https://api.first.org/data/v1/epss"

# The KEV catalog is ~1.7MB. Fetch it at most once per hour per process;
# every call after that reuses the in-memory copy.
_kev_cache = {"fetched_at": 0.0, "entries": {}}
KEV_CACHE_TTL_SECONDS = 3600


def _normalize_cve(raw: str) -> str | None:
    """Clean up a CVE ID. Returns the uppercase form, or None if invalid."""
    text = (raw or "").strip().upper()
    if not CVE_RE.match(text):
        return None
    return text


def _get_kev_entries():
    """Download the KEV catalog (cached hourly). Returns (entries, error).

    entries maps "CVE-2021-44228" -> the catalog record. error is a
    plain-English message when the download failed, else None.
    """
    now = time.time()
    if _kev_cache["entries"] and now - _kev_cache["fetched_at"] < KEV_CACHE_TTL_SECONDS:
        return _kev_cache["entries"], None
    try:
        resp = requests.get(KEV_FEED_URL, timeout=30)
        resp.raise_for_status()
        data = resp.json()
    except (requests.RequestException, ValueError):
        if _kev_cache["entries"]:
            # A stale copy beats no copy: use it and say so.
            return _kev_cache["entries"], (
                "Note: the KEV catalog couldn't be refreshed just now, "
                "so this uses a cached copy."
            )
        return {}, "Could not download the CISA KEV catalog. Check your internet connection and try again."
    entries = {}
    for vuln in data.get("vulnerabilities", []):
        cve_id = str(vuln.get("cveID", "")).strip().upper()
        if cve_id:
            entries[cve_id] = vuln
    _kev_cache["entries"] = entries
    _kev_cache["fetched_at"] = now
    return entries, None


def _get_epss(cve_id: str):
    """Ask FIRST's EPSS API for a CVE. Returns (score, percentile, error).

    score is 0.0-1.0 (probability of exploitation in the next 30 days).
    """
    try:
        resp = requests.get(EPSS_API_URL, params={"cve": cve_id}, timeout=NETWORK_TIMEOUT)
        resp.raise_for_status()
        data = resp.json()
    except (requests.RequestException, ValueError):
        return None, None, "Could not reach the EPSS score service."
    rows = data.get("data", [])
    if not rows:
        return None, None, "No EPSS score published for this CVE yet."
    try:
        score = float(rows[0].get("epss", 0))
        percentile = float(rows[0].get("percentile", 0))
    except (TypeError, ValueError):
        return None, None, "The EPSS service returned an unexpected answer."
    return score, percentile, None


def _epss_verdict(score: float) -> str:
    """Turn an EPSS probability into plain words."""
    pct = score * 100
    if pct >= 50:
        return f"CRITICAL likelihood: about {pct:.1f}% chance of exploitation in the next 30 days."
    if pct >= 10:
        return f"HIGH likelihood: about {pct:.1f}% chance of exploitation in the next 30 days."
    if pct >= 1:
        return f"MODERATE likelihood: about {pct:.1f}% chance of exploitation in the next 30 days."
    return f"LOW likelihood: about {pct:.2f}% chance of exploitation in the next 30 days."


@mcp.tool()
def check_cve(cve_id: str) -> str:
    """Checks whether a vulnerability is actively exploited right now and how likely it is to be exploited soon. Looks the CVE up in CISA's Known Exploited Vulnerabilities catalog (confirmed real-world exploitation, free public feed) and gets its EPSS score from FIRST (probability of exploitation in the next 30 days, free API). No keys or signup needed. Use when the user asks if a CVE is dangerous, being exploited, or worth patching first. Takes a CVE ID like "CVE-2021-44228". Returns a plain-English verdict, never a traceback."""
    cve = _normalize_cve(cve_id)
    if not cve:
        return (
            f"'{cve_id}' is not a valid CVE ID. They look like "
            "\"CVE-2021-44228\": CVE, a 4-digit year, then digits."
        )

    lines = [f"Vulnerability check: {cve}", ""]
    warnings = []

    # -- Question 1: actively exploited RIGHT NOW? (CISA KEV) --
    kev_entries, kev_error = _get_kev_entries()
    if kev_error and not kev_entries:
        lines.append(f"[!] KEV catalog: {kev_error}")
    else:
        if kev_error:
            warnings.append(kev_error)
        record = kev_entries.get(cve)
        if record:
            lines.append("[!] ACTIVELY EXPLOITED: this CVE is on CISA's Known Exploited")
            lines.append("    Vulnerabilities list, meaning real attackers are using it now.")
            lines.append(f"    Product: {record.get('vendorProject', '?')} {record.get('product', '')}".rstrip())
            lines.append(f"    Added to the list: {record.get('dateAdded', '?')}")
            lines.append(f"    Required action: {record.get('requiredAction', 'follow vendor guidance')}")
            short = (record.get("shortDescription", "") or "").strip()
            if short:
                lines.append(f"    What it is: {short[:300]}")
        else:
            lines.append("[+] Not on CISA's actively-exploited list right now.")
            lines.append("    (Absence from the list doesn't mean safe, only that CISA")
            lines.append("    hasn't confirmed real-world exploitation yet.)")
    lines.append("")

    # -- Question 2: likely to be exploited SOON? (EPSS) --
    score, percentile, epss_error = _get_epss(cve)
    if epss_error:
        lines.append(f"[!] EPSS score: {epss_error}")
    else:
        lines.append(f"[*] {_epss_verdict(score)}")
        lines.append(f"    (Higher than {percentile * 100:.1f}% of all scored CVEs.)")
    lines.append("")

    # -- The bottom line. --
    exploited = bool(kev_entries.get(cve)) if kev_entries else False
    if exploited:
        lines.append("Verdict: patch this immediately. It is being exploited in the wild today.")
    elif score is not None and score >= 0.1:
        lines.append("Verdict: not confirmed as exploited, but the exploitation odds are high. Patch soon.")
    elif score is not None:
        lines.append("Verdict: no confirmed exploitation and low predicted odds. Patch on your normal schedule.")
    else:
        lines.append("Verdict: partial data (one source unreachable). Treat unknown CVEs cautiously.")

    for w in warnings:
        lines.append("")
        lines.append(w)
    return "\n".join(lines)


# ===========================================================================
# TOOL 3: lookup_attack
# ===========================================================================
# MITRE ATT&CK is a public encyclopedia of how real attackers break in.
# Every technique has an ID like T1566 (phishing). This tool translates a
# technique ID or a keyword ("phishing", "ransomware") into plain English:
# what it is, how attackers use it, and how to defend.
#
# The technique data is bundled with this package (attack_techniques.json,
# trimmed from MITRE's public CTI feed), so lookups need no API key and no
# network at all. The bundle loads once and stays in memory.
# ===========================================================================

# Technique IDs look like T1566, or T1566.001 for sub-techniques.
TECHNIQUE_ID_RE = re.compile(r"^T\d{4}(\.\d{3})?$", re.IGNORECASE)

# One-line defense advice per MITRE tactic (the "why" behind the attack).
# These are standard industry practices, written in plain words.
TACTIC_DEFENSES = {
    "reconnaissance": "Limit what attackers can learn: minimize public info about your systems and staff.",
    "resource development": "Watch for lookalike domains and fake infrastructure impersonating your organization.",
    "initial access": "Patch public-facing systems fast, use phishing-resistant MFA, and filter email attachments.",
    "execution": "Restrict scripting tools and macros; application allowlisting stops unknown code from running.",
    "persistence": "Monitor auto-start locations, scheduled tasks, and new services for additions you didn't make.",
    "privilege escalation": "Follow least privilege: nobody (and no service) gets more access than the job needs.",
    "defense evasion": "Centralize logs where attackers can't delete them, and alert on log tampering.",
    "credential access": "Use MFA everywhere, long unique passwords via a manager, and monitor for mass login attempts.",
    "discovery": "Segment the network so one compromised machine can't see everything.",
    "lateral movement": "Segment the network and require MFA for remote access between machines.",
    "collection": "Monitor for unusual data access patterns and large outbound transfers.",
    "command and control": "Filter outbound traffic and DNS; alert on connections to unknown external servers.",
    "exfiltration": "Watch for large or unusual outbound data transfers, especially to new destinations.",
    "impact": "Keep offline backups and test restoring from them; that's what defeats ransomware.",
}

_techniques_cache = None


def _load_techniques() -> list:
    """Load the bundled ATT&CK techniques (once per process)."""
    global _techniques_cache
    if _techniques_cache is not None:
        return _techniques_cache
    data_path = Path(__file__).parent / "attack_techniques.json"
    try:
        with open(data_path, encoding="utf-8") as f:
            bundle = json.load(f)
        _techniques_cache = bundle.get("techniques", [])
    except (OSError, ValueError):
        _techniques_cache = []
    return _techniques_cache


def _find_by_id(techniques: list, tech_id: str):
    """Exact match on a technique ID like T1566."""
    wanted = tech_id.upper()
    for t in techniques:
        if t["id"].upper() == wanted:
            return t
    return None


def _find_by_keyword(techniques: list, keyword: str, limit: int = 5) -> list:
    """Keyword search over technique names first, then descriptions.

    Name matches rank above description matches. Returns up to `limit`.
    """
    kw = keyword.lower().strip()
    if not kw:
        return []
    name_hits, desc_hits = [], []
    for t in techniques:
        name = t["name"].lower()
        if kw in name:
            # Earlier occurrence + shorter name = better match.
            name_hits.append((name.index(kw), len(name), t))
        elif kw in t["description"].lower():
            desc_hits.append(t)
    name_hits.sort(key=lambda x: (x[0], x[1]))
    results = [t for _, _, t in name_hits]
    for t in desc_hits:
        if t not in results:
            results.append(t)
    return results[:limit]


def _format_technique(t: dict) -> str:
    """One technique, fully explained in plain English."""
    lines = [f"{t['id']}: {t['name']}", ""]
    tactics = ", ".join(t["tactics"]) if t["tactics"] else "general attack"
    lines.append(f"Stage of attack: {tactics}.")
    if t["platforms"]:
        lines.append(f"Targets: {', '.join(t['platforms'])}.")
    lines.append("")
    desc = t["description"].strip()
    # MITRE descriptions can run long; keep the first ~600 characters so the
    # answer stays readable, and say so honestly.
    if len(desc) > 600:
        desc = desc[:600].rsplit(" ", 1)[0] + "..."
    lines.append(f"What it is: {desc}")
    lines.append("")
    detection = t["detection"].strip()
    if detection:
        if len(detection) > 400:
            detection = detection[:400].rsplit(" ", 1)[0] + "..."
        lines.append(f"How to spot it: {detection}")
        lines.append("")
    defenses = []
    for tactic in t["tactics"]:
        advice = TACTIC_DEFENSES.get(tactic)
        if advice and advice not in defenses:
            defenses.append(advice)
    if defenses:
        lines.append("How to defend:")
        for d in defenses:
            lines.append(f"  - {d}")
    return "\n".join(lines)


@mcp.tool()
def lookup_attack(query: str) -> str:
    """Explains a cyber attack technique in plain English. Give a MITRE ATT&CK technique ID like "T1566" or a keyword like "phishing", and get back what the technique is, how attackers use it, how to spot it, and how to defend. Data comes from the public MITRE ATT&CK catalog bundled with this server: no API key, no network needed. Use when the user asks how an attack works, what a technique ID means, or how to defend against something. Defensive knowledge only: explains attacks so people can stop them, never how to carry them out."""
    techniques = _load_techniques()
    if not techniques:
        return (
            "The bundled attack-technique data could not be loaded. "
            "Reinstall the package and try again."
        )

    q = (query or "").strip()
    if not q:
        return (
            "Tell me which attack technique to look up: a technique ID like "
            "\"T1566\", or a keyword like \"phishing\"."
        )

    # -- ID lookup first: "T1566" or "t1566.001". --
    if TECHNIQUE_ID_RE.match(q):
        t = _find_by_id(techniques, q)
        if t:
            return _format_technique(t)
        return (
            f"No technique with ID '{q.upper()}' in the bundled catalog. "
            "Check the ID: they look like T1566, with an optional .001 suffix "
            "for sub-techniques."
        )

    # -- Keyword search: rank name matches above description matches. --
    matches = _find_by_keyword(techniques, q)
    if not matches:
        return (
            f"Nothing in the attack catalog matched '{q}'. Try a different "
            "keyword (e.g. \"phishing\", \"ransomware\", \"credential\") or a "
            "technique ID like \"T1566\"."
        )
    if len(matches) == 1:
        return _format_technique(matches[0])

    lines = [
        f"{len(matches)} techniques matched '{q}'. The closest:",
        "",
    ]
    for t in matches:
        tactics = ", ".join(t["tactics"]) if t["tactics"] else "general"
        lines.append(f"  - {t['id']}: {t['name']} ({tactics})")
    lines.append("")
    lines.append(
        "Ask again with a technique ID (e.g. \"T1566\") for the full explanation."
    )
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Start the server. When an assistant (like Claude Desktop) launches this
# file, it talks to the server through standard input/output. That's all
# this one line does: open for business.
# ---------------------------------------------------------------------------
def main() -> None:
    """Entry point for the `security-mcp` console script (pip/uvx installs)."""
    # FastMCP phones home to PyPI on every launch to check for its own
    # updates. That is slow, unnecessary for this server, and can crash the
    # whole startup in odd network setups (like proxied ones). Turn it off.
    import fastmcp

    fastmcp.settings.check_for_updates = "off"
    mcp.run()


if __name__ == "__main__":
    main()
