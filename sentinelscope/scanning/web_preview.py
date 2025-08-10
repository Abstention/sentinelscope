from __future__ import annotations

import re
from typing import Optional

import httpx

from sentinelscope.models import WebPreview


TITLE_RE = re.compile(r"<title>(.*?)</title>", re.IGNORECASE | re.DOTALL)


async def fetch_preview(url: str, timeout: float = 6.0) -> WebPreview:
    async with httpx.AsyncClient(follow_redirects=True, timeout=timeout) as client:
        resp = await client.get(url)
    text = resp.text[:10000] if isinstance(resp.text, str) else ""
    title_match: Optional[re.Match[str]] = TITLE_RE.search(text)
    title = title_match.group(1).strip() if title_match else None
    server = resp.headers.get("server")
    content_type = resp.headers.get("content-type")
    return WebPreview(url=url, status_code=resp.status_code, title=title, server=server, content_type=content_type)

