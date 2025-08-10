from __future__ import annotations

from typing import List

import httpx

from sentinelscope.models import CookieAssessment, CookieInfo


def _parse_set_cookie(header_value: str) -> CookieInfo:
    parts = [p.strip() for p in header_value.split(';')]
    name_value = parts[0]
    name = name_value.split('=')[0]
    attrs = {p.split('=')[0].lower(): (p.split('=')[1] if '=' in p else True) for p in parts[1:]}
    secure = bool(attrs.get('secure'))
    http_only = bool(attrs.get('httponly'))
    same_site = attrs.get('samesite') if isinstance(attrs.get('samesite'), str) else None
    issues: List[str] = []
    if not secure:
        issues.append('Missing Secure')
    if not http_only:
        issues.append('Missing HttpOnly')
    if not same_site:
        issues.append('Missing SameSite')
    return CookieInfo(name=name, secure=secure, http_only=http_only, same_site=same_site, issues=issues)


async def analyze_cookies(url: str, timeout: float = 6.0) -> CookieAssessment:
    async with httpx.AsyncClient(follow_redirects=True, timeout=timeout) as client:
        resp = await client.get(url)
    cookies_headers = resp.headers.get_list('set-cookie') if hasattr(resp.headers, 'get_list') else resp.headers.get('set-cookie', '').split('\n')
    cookies: List[CookieInfo] = []
    for h in cookies_headers:
        if not h:
            continue
        try:
            cookies.append(_parse_set_cookie(h))
        except Exception:
            continue
    return CookieAssessment(url=url, cookies=cookies)

