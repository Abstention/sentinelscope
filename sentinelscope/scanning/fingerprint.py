from __future__ import annotations

from typing import List, Optional

import httpx

from sentinelscope.models import WebFingerprint


WAF_SIGNS = {
    'cloudflare': ['cloudflare', '__cf_bm', 'cf-ray'],
    'akamai': ['akamai', 'aka-cache', 'akamai-ghost'],
    'fastly': ['fastly', 'x-served-by'],
}


async def fingerprint_web(url: str, timeout: float = 6.0) -> WebFingerprint:
    async with httpx.AsyncClient(follow_redirects=True, timeout=timeout) as client:
        resp = await client.get(url)
    server = resp.headers.get('server')
    waf: Optional[str] = None
    header_blob = ' '.join(f"{k}:{v}" for k, v in resp.headers.items()).lower()
    for vendor, tokens in WAF_SIGNS.items():
        if any(t in header_blob for t in tokens):
            waf = vendor
            break
    techs: List[str] = []
    if 'x-powered-by' in resp.headers:
        techs.append(resp.headers.get('x-powered-by'))
    # Use the final effective URL to reflect redirects and scheme changes
    return WebFingerprint(url=str(resp.url), server=server, waf_or_cdn=waf, technologies=techs)

