from __future__ import annotations

import socket
import ssl
from datetime import datetime
from typing import Dict, List

from sentinelscope.models import TLSInfo


def _parse_name(obj) -> Dict[str, str]:
    d: Dict[str, str] = {}
    for tup in obj:  # list of tuples like ((('commonName', 'example.com'),), ...)
        for k, v in tup:
            d[str(k)] = str(v)
    return d


def _convert_asn1_date(value: str) -> datetime:
    # Format is 'Jun 10 12:00:00 2025 GMT'
    return datetime.strptime(value, "%b %d %H:%M:%S %Y %Z")


def get_tls_info(domain: str, port: int = 443, timeout: float = 3.0) -> TLSInfo:
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    warnings: List[str] = []
    protocol: str | None = None
    valid_from = None
    valid_to = None
    subject = None
    issuer = None
    sans: List[str] = []

    try:
        with socket.create_connection((domain, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                protocol = ssock.version()
                cert = ssock.getpeercert()
                if cert:
                    if 'notBefore' in cert:
                        valid_from = _convert_asn1_date(cert['notBefore'])
                    if 'notAfter' in cert:
                        valid_to = _convert_asn1_date(cert['notAfter'])
                    if 'subject' in cert:
                        subject = _parse_name(cert['subject'])
                    if 'issuer' in cert:
                        issuer = _parse_name(cert['issuer'])
                    for typ, vals in cert.get('subjectAltName', []):
                        if typ == 'DNS':
                            sans.append(vals)
    except Exception as e:  # noqa: BLE001
        warnings.append(f"TLS check failed: {e}")

    days_until_expiry = None
    if valid_to:
        days_until_expiry = (valid_to - datetime.utcnow()).days
        if days_until_expiry is not None and days_until_expiry < 30:
            warnings.append("Certificate expiring within 30 days")

    return TLSInfo(
        domain=domain,
        port=port,
        valid_from=valid_from,
        valid_to=valid_to,
        days_until_expiry=days_until_expiry,
        subject=subject,
        issuer=issuer,
        subject_alternative_names=sans,
        protocol=protocol,
        warnings=warnings,
    )

