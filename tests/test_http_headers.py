from sentinelscope.scanning.http_headers import evaluate_security_headers, _grade_from_findings


def test_grading_good_headers():
    headers = {
        "Content-Security-Policy": "default-src 'self'",
        "Strict-Transport-Security": "max-age=63072000; includeSubDomains; preload",
        "X-Content-Type-Options": "nosniff",
        "X-Frame-Options": "DENY",
        "Referrer-Policy": "no-referrer",
        "Permissions-Policy": "camera=()",
    }
    findings = evaluate_security_headers(headers)
    grade, score = _grade_from_findings(findings)
    assert grade in {"A+", "A"}
    assert 90 <= score <= 100


def test_grading_missing_headers():
    headers = {
        "X-Frame-Options": "SAMEORIGIN",
    }
    findings = evaluate_security_headers(headers)
    grade, score = _grade_from_findings(findings)
    assert grade in {"C", "D", "F"}
    assert 0 <= score <= 80

