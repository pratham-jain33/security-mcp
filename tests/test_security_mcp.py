"""Tests for security-mcp. Unit tests use mocked network; live tests are
opt-in via SHIELD_LIVE=1 and hit the real internet."""

import asyncio
import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from security_mcp import server  # noqa: E402

LIVE = os.environ.get("SHIELD_LIVE") == "1"
needs_live = pytest.mark.skipif(not LIVE, reason="live test: set SHIELD_LIVE=1")


# ---------------------------------------------------------------------------
# Tool registration
# ---------------------------------------------------------------------------

def test_tools_registered():
    tools = {t.name: t for t in asyncio.run(server.mcp.list_tools())}
    assert set(tools) == {"audit_site", "check_cve", "lookup_attack"}
    for name, tool in tools.items():
        assert tool.description and len(tool.description) > 50, name
    params = tools["audit_site"].parameters
    assert set(params["properties"]) == {"domain"}
    assert set(tools["check_cve"].parameters["properties"]) == {"cve_id"}
    assert set(tools["lookup_attack"].parameters["properties"]) == {"query"}


# ---------------------------------------------------------------------------
# _clean_domain
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("raw,expected", [
    ("example.com", "example.com"),
    ("https://example.com/path?q=1", "example.com"),
    ("http://EXAMPLE.COM.", "example.com"),
    ("  sub.example.co.uk  ", "sub.example.co.uk"),
    ("example.com:8080/page", "example.com"),
    ("not a domain!!", None),
    ("", None),
    ("https://", None),
])
def test_clean_domain(raw, expected):
    assert server._clean_domain(raw) == expected


# ---------------------------------------------------------------------------
# CVE validation
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("raw,expected", [
    ("CVE-2021-44228", "CVE-2021-44228"),
    ("cve-2021-44228", "CVE-2021-44228"),
    ("  CVE-2024-1234  ", "CVE-2024-1234"),
    ("CVE-21-44228", None),      # year must be 4 digits
    ("CVE-2021-123", None),      # number must be 4+ digits
    ("XVE-2021-44228", None),
    ("", None),
])
def test_normalize_cve(raw, expected):
    assert server._normalize_cve(raw) == expected


def test_check_cve_rejects_bad_format_without_network():
    out = server.check_cve("not-a-cve")
    assert "not a valid CVE ID" in out
    assert "CVE-2021-44228" in out  # shows the expected shape


# ---------------------------------------------------------------------------
# Grading logic (pure, no network)
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("score,critical,expected", [
    (100, False, "A+"), (95, False, "A+"), (94, False, "A"),
    (90, False, "A"), (85, False, "B"), (70, False, "C"),
    (55, False, "D"), (54, False, "F"), (0, False, "F"),
    (100, True, "F"),  # critical failure always caps at F
])
def test_score_to_grade(score, critical, expected):
    assert server._score_to_grade(score, critical) == expected


def _finding(penalty):
    return {"label": "x", "status": "fail", "penalty": penalty, "detail": "x"}


def test_grade_site_adds_penalties():
    grade, score, critical = server._grade_site(
        [_finding(15), _finding(5)],
        {"penalty": 10, "critical": False},
        [_finding(10)],
    )
    assert score == 60
    assert grade == "D"
    assert critical is False


def test_grade_site_critical():
    grade, score, critical = server._grade_site(
        [], {"penalty": 60, "critical": True}, []
    )
    assert grade == "F" and critical is True


# ---------------------------------------------------------------------------
# Header checks (pure logic on the HEADER_CHECKS table)
# ---------------------------------------------------------------------------

def _run_header_check(label, value, headers=None):
    spec = next(s for s in server.HEADER_CHECKS if s["label"] == label)
    headers = headers or {}
    try:
        return spec["check"](value, headers)
    except TypeError:
        return spec["check"](value)


def test_header_checks():
    assert _run_header_check("HSTS", "max-age=31536000; includeSubDomains") is True
    assert _run_header_check("HSTS", None) is False
    assert _run_header_check("CSP", "default-src 'self'") is True
    assert _run_header_check("CSP", None) is False
    # X-Frame-Options passes via frame-ancestors in CSP too.
    assert _run_header_check("X-Frame-Options", "DENY") is True
    assert _run_header_check("X-Frame-Options", None,
                             {"content-security-policy": "frame-ancestors 'none'"}) is True
    assert _run_header_check("X-Frame-Options", None) is False
    assert _run_header_check("X-Content-Type-Options", "nosniff") is True
    assert _run_header_check("X-Content-Type-Options", "wrong") is False


# ---------------------------------------------------------------------------
# SSL check with mocked sockets
# ---------------------------------------------------------------------------

class _FakeTLS:
    def __init__(self, cert=None, fail=False):
        self._cert = cert
        self._fail = fail

    def __enter__(self):
        if self._fail:
            raise OSError("handshake failed")
        return self

    def __exit__(self, *a):
        return False

    def getpeercert(self):
        return self._cert


def _patch_tls(monkeypatch, cert=None, fail=False):
    def fake_connect_tls(domain):
        return _FakeTLS(cert, fail)
    monkeypatch.setattr(server, "_connect_tls", fake_connect_tls)


def _cert(not_after, org="Test CA"):
    return {
        "notAfter": not_after,
        "issuer": ((("organizationName", org),),),
    }


def test_ssl_valid_long(monkeypatch):
    _patch_tls(monkeypatch, _cert("Sep 29 12:00:00 2030 GMT"))
    r = server._check_ssl("example.com")
    assert r["ok"] is True and r["days_left"] > 300 and r["penalty"] == 0


def test_ssl_expiring_soon(monkeypatch):
    from datetime import datetime, timedelta, timezone
    soon = (datetime.now(timezone.utc) + timedelta(days=5)).strftime("%b %d %H:%M:%S %Y GMT")
    _patch_tls(monkeypatch, _cert(soon))
    r = server._check_ssl("example.com")
    assert r["ok"] is True and r["penalty"] == 15
    assert "expires in" in r["detail"] and "days" in r["detail"]


def test_ssl_expired(monkeypatch):
    _patch_tls(monkeypatch, _cert("Jan 01 00:00:00 2020 GMT"))
    r = server._check_ssl("example.com")
    assert r["ok"] is False and r["critical"] is True and "EXPIRED" in r["detail"]


def test_ssl_handshake_fails(monkeypatch):
    _patch_tls(monkeypatch, fail=True)
    r = server._check_ssl("example.com")
    assert r["critical"] is True and "trusted HTTPS connection" in r["detail"]


# ---------------------------------------------------------------------------
# Email-auth checks with mocked DNS
# ---------------------------------------------------------------------------

def _patch_txt(monkeypatch, mapping):
    def fake_txt(name):
        return mapping.get(name, [])
    monkeypatch.setattr(server, "_txt_records", fake_txt)


def test_email_auth_all_good(monkeypatch):
    _patch_txt(monkeypatch, {
        "example.com": ["v=spf1 include:_spf.google.com -all"],
        "_dmarc.example.com": ["v=DMARC1; p=reject;"],
        "google._domainkey.example.com": ["v=DKIM1; k=rsa; p=ABCDEF"],
    })
    findings = {f["label"]: f for f in server._check_email_auth("example.com")}
    assert findings["SPF"]["status"] == "pass"
    assert findings["DMARC"]["status"] == "pass"
    assert findings["DKIM"]["status"] == "pass"


def test_email_auth_all_missing(monkeypatch):
    _patch_txt(monkeypatch, {})
    findings = {f["label"]: f for f in server._check_email_auth("example.com")}
    assert findings["SPF"]["status"] == "fail"
    assert findings["DMARC"]["status"] == "fail"
    assert findings["DKIM"]["status"] == "warn"  # warn, not fail: selectors are a guess


def test_email_auth_weak_spf_and_dmarc_none(monkeypatch):
    _patch_txt(monkeypatch, {
        "example.com": ["v=spf1 ?all"],
        "_dmarc.example.com": ["v=DMARC1; p=none;"],
    })
    findings = {f["label"]: f for f in server._check_email_auth("example.com")}
    assert findings["SPF"]["status"] == "warn"
    assert findings["DMARC"]["status"] == "warn"


# ---------------------------------------------------------------------------
# check_cve with mocked feeds
# ---------------------------------------------------------------------------

def _patch_feeds(monkeypatch, kev_record=None, epss=None):
    entries = {"CVE-2021-44228": kev_record} if kev_record else {}
    monkeypatch.setattr(server, "_get_kev_entries", lambda: (entries, None))
    if epss is None:
        monkeypatch.setattr(server, "_get_epss", lambda cve: (None, None, "no score"))
    else:
        score, pct = epss
        monkeypatch.setattr(server, "_get_epss", lambda cve: (score, pct, None))


KEV_RECORD = {
    "cveID": "CVE-2021-44228",
    "vendorProject": "Apache",
    "product": "Log4j2",
    "dateAdded": "2021-12-10",
    "requiredAction": "Apply updates.",
    "shortDescription": "Log4j2 remote code execution.",
}


def test_check_cve_exploited(monkeypatch):
    _patch_feeds(monkeypatch, kev_record=KEV_RECORD, epss=(0.97, 0.99))
    out = server.check_cve("cve-2021-44228")
    assert "ACTIVELY EXPLOITED" in out
    assert "Apache" in out
    assert "patch this immediately" in out


def test_check_cve_not_exploited_high_epss(monkeypatch):
    _patch_feeds(monkeypatch, kev_record=None, epss=(0.3, 0.9))
    out = server.check_cve("CVE-2021-44228")
    assert "Not on CISA's actively-exploited list" in out
    assert "HIGH likelihood" in out
    assert "Patch soon" in out


def test_check_cve_quiet(monkeypatch):
    _patch_feeds(monkeypatch, kev_record=None, epss=(0.001, 0.1))
    out = server.check_cve("CVE-2021-44228")
    assert "LOW likelihood" in out
    assert "normal schedule" in out


def test_check_cve_no_epss_data(monkeypatch):
    _patch_feeds(monkeypatch, kev_record=None, epss=None)
    out = server.check_cve("CVE-2021-44228")
    assert "EPSS score: no score" in out
    assert "partial data" in out


# ---------------------------------------------------------------------------
# lookup_attack against the real bundled data (no network needed)
# ---------------------------------------------------------------------------

def test_lookup_by_id():
    out = server.lookup_attack("T1566")
    assert "T1566: Phishing" in out
    assert "How to defend" in out


def test_lookup_by_id_lowercase_and_subtechnique():
    out = server.lookup_attack("t1059")
    assert "T1059" in out  # Command and Scripting Interpreter
    out2 = server.lookup_attack("T1566.001")
    assert "T1566.001" in out2  # Spearphishing Attachment


def test_lookup_unknown_id():
    out = server.lookup_attack("T9999")
    assert "No technique with ID" in out


def test_lookup_keyword_multiple():
    out = server.lookup_attack("ransomware")
    assert "matched" in out and "technique ID" in out


def test_lookup_keyword_no_match():
    out = server.lookup_attack("zzzznothinghere")
    assert "Nothing in the attack catalog matched" in out


def test_lookup_empty():
    out = server.lookup_attack("   ")
    assert "which attack technique" in out


def test_technique_bundle_loads():
    techs = server._load_techniques()
    assert len(techs) > 600
    assert all(t["id"] and t["name"] and t["description"] for t in techs)


# ---------------------------------------------------------------------------
# audit_site with fully mocked network
# ---------------------------------------------------------------------------

def _patch_audit_net(monkeypatch):
    headers = {
        "strict-transport-security": "max-age=31536000",
        "content-security-policy": "default-src 'self'",
        "x-frame-options": "DENY",
        "x-content-type-options": "nosniff",
        "referrer-policy": "no-referrer",
        "permissions-policy": "camera=()",
    }
    monkeypatch.setattr(server, "_fetch_headers", lambda d: (headers, f"https://{d}/", None))
    _patch_tls(monkeypatch, _cert("Sep 29 12:00:00 2030 GMT", org="Good CA"))
    _patch_txt(monkeypatch, {
        "example.com": ["v=spf1 -all"],
        "_dmarc.example.com": ["v=DMARC1; p=reject;"],
        "default._domainkey.example.com": ["v=DKIM1; p=XYZ"],
    })


def test_audit_site_all_good_mocked(monkeypatch):
    _patch_audit_net(monkeypatch)
    out = server.audit_site("https://example.com/some/page")
    assert "Grade: A+" in out
    assert "example.com" in out


def test_audit_site_bad_domain():
    out = server.audit_site("not a domain!!")
    assert "doesn't look like a valid domain" in out


def test_audit_site_https_down(monkeypatch):
    monkeypatch.setattr(server, "_fetch_headers",
                        lambda d: (None, None, server._plain_error("x")))
    _patch_tls(monkeypatch, fail=True)
    _patch_txt(monkeypatch, {})
    out = server.audit_site("example.com")
    assert "Grade: F" in out


# ---------------------------------------------------------------------------
# DNS-over-HTTPS fallback parsing
# ---------------------------------------------------------------------------

class _FakeDohResp:
    def __init__(self, payload):
        self._payload = payload

    def json(self):
        return self._payload


def test_txt_records_doh_handles_quoted_and_unquoted(monkeypatch):
    # Google style: unquoted data. Cloudflare style: quoted chunks.
    payload = {
        "Status": 0,
        "Answer": [
            {"name": "x.", "type": 16, "data": "v=spf1 -all"},
            {"name": "x.", "type": 16, "data": '"v=DKIM1;" "k=rsa; p=ABC"'},
            {"name": "x.", "type": 28, "data": "not-txt"},  # AAAA: ignored
        ],
    }
    monkeypatch.setattr(
        server.requests, "get", lambda *a, **k: _FakeDohResp(payload)
    )
    records = server._txt_records_doh("example.com")
    assert records == ["v=spf1 -all", "v=DKIM1;k=rsa; p=ABC"]


def test_txt_records_doh_all_providers_fail(monkeypatch):
    def boom(*a, **k):
        raise server.requests.RequestException("down")
    monkeypatch.setattr(server.requests, "get", boom)
    assert server._txt_records_doh("example.com") == []


# ---------------------------------------------------------------------------
# Live smoke tests (real network). Run with SHIELD_LIVE=1.
# ---------------------------------------------------------------------------

@needs_live
def test_live_audit_example_com():
    out = server.audit_site("example.com")
    assert "Grade:" in out and "SSL certificate" in out
    print("\n" + out)


@needs_live
def test_live_check_cve_log4shell():
    out = server.check_cve("CVE-2021-44228")
    assert "ACTIVELY EXPLOITED" in out
    print("\n" + out)


@needs_live
def test_live_lookup_attack():
    out = server.lookup_attack("T1566")
    assert "Phishing" in out
