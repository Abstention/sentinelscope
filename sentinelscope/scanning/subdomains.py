from __future__ import annotations

import asyncio
import json
from typing import List, Set, Dict

import dns.asyncresolver
import httpx

from sentinelscope.models import SubdomainsResult


WORDLIST = [
    "www", "api", "dev", "staging", "test", "mail", "blog", "app", "cdn", "static",
]


async def _resolve(hostname: str, timeout: float = 2.0) -> bool:
    try:
        resolver = dns.asyncresolver.Resolver()
        resolver.lifetime = timeout
        await resolver.resolve(hostname, "A")
        return True
    except Exception:  # noqa: BLE001
        return False


async def _from_crtsh(domain: str) -> List[str]:
    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    try:
        async with httpx.AsyncClient(timeout=8.0) as client:
            r = await client.get(url)
            if r.status_code != 200:
                return []
            data = json.loads(r.text)
            names: Set[str] = set()
            for entry in data:
                name_value: str = entry.get("name_value", "")
                for n in name_value.split("\n"):
                    n = n.strip().lower()
                    if n.endswith(domain.lower()):
                        names.add(n)
            return sorted(names)
    except Exception:
        return []


async def enumerate_subdomains(root_domain: str, concurrent_dns: int = 50) -> SubdomainsResult:
    discovered: Set[str] = set()
    sources: Dict[str, int] = {}

    # CT source
    ct = await _from_crtsh(root_domain)
    discovered.update(ct)
    sources["crt.sh"] = len(ct)

    # wordlist DNS source
    candidates = [f"{w}.{root_domain}" for w in WORDLIST]
    semaphore = asyncio.Semaphore(concurrent_dns)

    async def check(name: str) -> None:
        async with semaphore:
            if await _resolve(name):
                discovered.add(name)

    await asyncio.gather(*(check(c) for c in candidates))
    sources["dns-wordlist"] = len([c for c in candidates if c in discovered])

    return SubdomainsResult(root_domain=root_domain, discovered=sorted(discovered), sources=sources)

