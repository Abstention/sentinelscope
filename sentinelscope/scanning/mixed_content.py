from __future__ import annotations

import re

import httpx

from sentinelscope.models import MixedContentReport


INSECURE_RE = re.compile(r"http://[^\s'\"]+", re.IGNORECASE)


async def check_mixed_content(url: str, timeout: float = 6.0) -> MixedContentReport:
    try:
        async with httpx.AsyncClient(follow_redirects=True, timeout=timeout) as client:
            resp = await client.get(url)
        text = resp.text or ""
        matches = INSECURE_RE.findall(text)
        examples = list(dict.fromkeys(matches))[:10]
        return MixedContentReport(url=url, insecure_reference_count=len(matches), examples=examples)
    except Exception:
        return MixedContentReport(url=url, insecure_reference_count=0, examples=[])

