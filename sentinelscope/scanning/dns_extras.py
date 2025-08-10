from __future__ import annotations

from typing import List

import dns.resolver

from sentinelscope.models import DNSExtras


def query_txt(name: str) -> List[str]:
    try:
        return [rdata.to_text().strip('"') for rdata in dns.resolver.resolve(name, 'TXT')]
    except Exception:
        return []


def query_caa(domain: str) -> List[str]:
    try:
        return [rdata.to_text() for rdata in dns.resolver.resolve(domain, 'CAA')]
    except Exception:
        return []


def check_dnssec(domain: str) -> bool:
    # Heuristic: presence of DNSKEY records indicates DNSSEC configured
    try:
        list(dns.resolver.resolve(domain, 'DNSKEY'))
        return True
    except Exception:
        return False


def gather_dns_extras(domain: str) -> DNSExtras:
    return DNSExtras(domain=domain, dnssec_present=check_dnssec(domain), caa_records=query_caa(domain))

