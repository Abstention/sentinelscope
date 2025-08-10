from __future__ import annotations

from typing import List, Optional

import httpx

from sentinelscope.models import SecurityTxt


async def fetch_security_txt(domain: str, timeout: float = 5.0) -> SecurityTxt:
    urls = [f"https://{domain}/.well-known/security.txt", f"https://{domain}/security.txt"]
    text: Optional[str] = None
    for u in urls:
        try:
            async with httpx.AsyncClient(timeout=timeout, follow_redirects=True) as client:
                r = await client.get(u)
                if r.status_code == 200 and r.text:
                    text = r.text
                    url = u
                    break
        except Exception:
            continue
    if text is None:
        return SecurityTxt(url=urls[0], found=False)
    contacts: List[str] = []
    policy: Optional[str] = None
    expires: Optional[str] = None
    for line in text.splitlines():
        if line.lower().startswith("contact:"):
            contacts.append(line.split(":", 1)[1].strip())
        elif line.lower().startswith("policy:"):
            policy = line.split(":", 1)[1].strip()
        elif line.lower().startswith("expires:"):
            expires = line.split(":", 1)[1].strip()
    return SecurityTxt(url=url, found=True, contacts=contacts, policy=policy, expires=expires)

