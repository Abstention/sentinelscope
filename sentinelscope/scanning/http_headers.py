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


def evaluate_security_headers(headers: Dict[str, str], *, is_https: bool = True) -> List[HeaderFinding]:
    lower = {k.lower(): v for k, v in headers.items()}
    findings: List[HeaderFinding] = []

    # Baseline presence
    for key, rec in SECURITY_HEADERS.items():
        findings.append(
            HeaderFinding(header=key, present=key in lower, recommendation=None if key in lower else rec)
        )

    # Quality checks
    # CSP: avoid wildcards/unsafe-inline; encourage default-src 'self'
    if 'content-security-policy' in lower:
        csp_value = str(lower['content-security-policy'])
        csp_value_lower = csp_value.lower()
        if "unsafe-inline" in csp_value_lower or "*" in csp_value_lower:
            findings.append(
                HeaderFinding(
                    header="content-security-policy",
                    present=True,
                    recommendation="Avoid wildcard or unsafe-inline in CSP for stricter policy",
                )
            )
        if 'default-src' not in csp_value_lower:
            findings.append(
                HeaderFinding(
                    header="content-security-policy",
                    present=True,
                    recommendation="Define a base policy (e.g., default-src 'self')",
                )
            )

    # HSTS: require includeSubDomains, recommend preload, and >= 180 days max-age
    if is_https and 'strict-transport-security' in lower:
        hsts_value = str(lower['strict-transport-security'])
        hsts_lower = hsts_value.lower()
        include_ok = 'includesubdomains' in hsts_lower
        preload_ok = 'preload' in hsts_lower
        max_age_ok = True
        try:
            # naive parse for max-age
            import re as _re

            m = _re.search(r"max-age\s*=\s*(\d+)", hsts_lower)
            if m:
                max_age_ok = int(m.group(1)) >= 15552000  # 180 days
        except Exception:  # noqa: BLE001
            max_age_ok = True
        if not include_ok or not preload_ok or not max_age_ok:
            missing_parts = []
            if not include_ok:
                missing_parts.append("includeSubDomains")
            if not preload_ok:
                missing_parts.append("preload")
            if not max_age_ok:
                missing_parts.append("max-age>=15552000")
            findings.append(
                HeaderFinding(
                    header="strict-transport-security",
                    present=True,
                    recommendation="Improve HSTS: " + ", ".join(missing_parts),
                )
            )

    # X-Content-Type-Options must be 'nosniff'
    if 'x-content-type-options' in lower:
        v = str(lower['x-content-type-options']).strip().lower()
        if v != 'nosniff':
            findings.append(
                HeaderFinding(
                    header="x-content-type-options",
                    present=True,
                    recommendation="Set X-Content-Type-Options to nosniff",
                )
            )

    # X-Frame-Options should be DENY or SAMEORIGIN
    if 'x-frame-options' in lower:
        v = str(lower['x-frame-options']).strip().lower()
        if v not in {"deny", "sameorigin"}:
            findings.append(
                HeaderFinding(
                    header="x-frame-options",
                    present=True,
                    recommendation="Use DENY or SAMEORIGIN for X-Frame-Options",
                )
            )

    # Referrer-Policy strong values
    if 'referrer-policy' in lower:
        v = str(lower['referrer-policy']).strip().lower()
        if v not in {"no-referrer", "strict-origin-when-cross-origin"}:
            findings.append(
                HeaderFinding(
                    header="referrer-policy",
                    present=True,
                    recommendation="Prefer no-referrer or strict-origin-when-cross-origin",
                )
            )

    # Permissions-Policy should not be wildcard-permissive
    if 'permissions-policy' in lower:
        v = str(lower['permissions-policy']).strip().lower()
        if not v or '*' in v or '=(*)' in v:
            findings.append(
                HeaderFinding(
                    header="permissions-policy",
                    present=True,
                    recommendation="Tighten Permissions-Policy (avoid wildcards; disable features by default)",
                )
            )

    # If site is served over HTTP, we cannot rely on HSTS at first request.
    # Recommend migrating to HTTPS.
    if not is_https:
        findings.append(
            HeaderFinding(
                header="strict-transport-security",
                present=False,
                recommendation="Serve over HTTPS and enable HSTS",
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
        effective_url = str(resp.url)
        is_https = effective_url.lower().startswith("https://")
        findings = evaluate_security_headers(dict(resp.headers), is_https=is_https)
        grade, score = _grade_from_findings(findings)
        return SecurityHeadersAssessment(url=effective_url, findings=findings, grade=grade, score=score)
    except Exception:
        # Network/HTTP errors should not crash the scan; return neutral result
        return SecurityHeadersAssessment(url=url, findings=[], grade="N/A", score=0)

