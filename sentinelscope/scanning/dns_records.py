from __future__ import annotations

from typing import List

import dns.resolver

from sentinelscope.models import DNSAssessment


def _txt_values(domain: str) -> List[str]:
    try:
        return [b"".join(rdata.strings).decode("utf-8", errors="ignore") for rdata in dns.resolver.resolve(domain, "TXT")]
    except Exception:
        return []


def _records(domain: str, rtype: str) -> List[str]:
    try:
        answers = dns.resolver.resolve(domain, rtype)
        return [rdata.to_text() for rdata in answers]
    except Exception:
        return []


def assess_dns(domain: str) -> DNSAssessment:
    a_records = _records(domain, "A")
    aaaa_records = _records(domain, "AAAA")
    mx_records = _records(domain, "MX")
    txt_records = _txt_values(domain)

    spf_present = any(v.lower().startswith("v=spf1") for v in txt_records)
    spf_policy = None
    spf_recommendation = None
    if spf_present:
        spf = next(v for v in txt_records if v.lower().startswith("v=spf1"))
        for p in ["-all", "~all", "?all", "+all"]:
            if p in spf:
                spf_policy = p
                break
        if spf_policy in {"?all", "+all", None}:
            spf_recommendation = "Tighten SPF policy to -all or ~all"

    dmarc_present = any(v.lower().startswith("v=dmarc1") for v in txt_records)
    dmarc_policy = None
    dmarc_recommendation = None
    if dmarc_present:
        dmarc = next(v for v in txt_records if v.lower().startswith("v=dmarc1"))
        # parse p=reject|quarantine|none
        for tok in dmarc.split(";"):
            tok = tok.strip().lower()
            if tok.startswith("p="):
                dmarc_policy = tok.split("=", 1)[1]
        if dmarc_policy in {None, "none"}:
            dmarc_recommendation = "Set DMARC policy to quarantine or reject"

    return DNSAssessment(
        domain=domain,
        a_records=a_records,
        aaaa_records=aaaa_records,
        mx_records=mx_records,
        txt_records=txt_records,
        spf_present=spf_present,
        spf_policy=spf_policy,
        spf_recommendation=spf_recommendation,
        dmarc_present=dmarc_present,
        dmarc_policy=dmarc_policy,
        dmarc_recommendation=dmarc_recommendation,
    )

