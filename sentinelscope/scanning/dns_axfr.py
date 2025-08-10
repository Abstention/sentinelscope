from __future__ import annotations

from typing import List

import dns.resolver
import dns.query
import dns.zone

from sentinelscope.models import DNSAxfrCheck


def check_dns_axfr(domain: str, timeout: float = 3.0) -> DNSAxfrCheck:
    attempted: List[str] = []
    allowed: List[str] = []
    try:
        answers = dns.resolver.resolve(domain, 'NS', lifetime=timeout)
        ns_list = [rdata.to_text().strip('.') for rdata in answers]
    except Exception:
        ns_list = []
    for ns in ns_list:
        attempted.append(ns)
        try:
            z = dns.zone.from_xfr(dns.query.xfr(ns, domain, timeout=timeout))
            if z is not None:
                allowed.append(ns)
        except Exception:
            continue
    return DNSAxfrCheck(domain=domain, attempted_ns=attempted, axfr_allowed_on=allowed)

