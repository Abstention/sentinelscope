from __future__ import annotations

from typing import Dict, List

import httpx

from sentinelscope.models import HeaderFinding, SecurityHeadersAssessment


SECURITY_HEADERS = {
    "content-security-policy": "Set a strict CSP to mitigate XSS (e.g., default-src 'self')",
    "strict-transport-security": "Enable HSTS to enforce HTTPS (includeSubDomains; preload)",
    "x-content-type-options": "Set to nosniff to prevent MIME sniffing",
    "x-frame-options": "Set to DENY or SAMEORIGIN to mitigate clickjacking",
    "referrer-policy": "Set to no-referrer or strict-origin-when-cross-origin",
    "permissions-policy": "Restrict powerful browser features",
}


def evaluate_security_headers(headers: Dict[str, str]) -> List[HeaderFinding]:
    lower = {k.lower(): v for k, v in headers.items()}
    findings: List[HeaderFinding] = []
    for key, rec in SECURITY_HEADERS.items():
        findings.append(
            HeaderFinding(header=key, present=key in lower, recommendation=None if key in lower else rec)
        )
    # Quality checks
    if 'content-security-policy' in lower:
        csp = lower['content-security-policy']
        if "unsafe-inline" in csp or "*" in csp:
            findings.append(
                HeaderFinding(
                    header="content-security-policy",
                    present=True,
                    recommendation="Avoid wildcard or unsafe-inline in CSP for stricter policy",
                )
            )
    if 'strict-transport-security' in lower:
        hsts = lower['strict-transport-security']
        if 'max-age' in hsts and 'includeSubDomains' not in hsts and 'includesubdomains' not in hsts:
            findings.append(
                HeaderFinding(
                    header="strict-transport-security",
                    present=True,
                    recommendation="Consider includeSubDomains and preload for robust HSTS",
                )
            )
    return findings


def _grade_from_findings(findings: List[HeaderFinding]) -> tuple[str, int]:
    present = sum(1 for f in findings if f.recommendation is None and f.present)
    total = len(SECURITY_HEADERS)
    # Additional recommendations count as deductions
    deductions = sum(1 for f in findings if f.recommendation is not None)
    raw_score = max(0, min(100, int((present / total) * 100) - deductions * 5))
    if raw_score >= 95:
        return "A+", raw_score
    if raw_score >= 90:
        return "A", raw_score
    if raw_score >= 80:
        return "B", raw_score
    if raw_score >= 70:
        return "C", raw_score
    if raw_score >= 60:
        return "D", raw_score
    return "F", raw_score


async def analyze_security_headers(url: str, timeout: float = 5.0) -> SecurityHeadersAssessment:
    try:
        async with httpx.AsyncClient(follow_redirects=True, timeout=timeout) as client:
            resp = await client.get(url)
        findings = evaluate_security_headers(dict(resp.headers))
        grade, score = _grade_from_findings(findings)
        return SecurityHeadersAssessment(url=url, findings=findings, grade=grade, score=score)
    except Exception:
        # Network/HTTP errors should not crash the scan; return neutral result
        return SecurityHeadersAssessment(url=url, findings=[], grade="N/A", score=0)

