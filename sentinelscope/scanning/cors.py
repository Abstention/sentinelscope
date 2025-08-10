from __future__ import annotations

from typing import List, Optional

import httpx

from sentinelscope.models import CORSAssessment


async def analyze_cors(url: str, timeout: float = 6.0) -> CORSAssessment:
    try:
        async with httpx.AsyncClient(follow_redirects=True, timeout=timeout) as client:
            resp = await client.get(url, headers={"Origin": "https://example.com"})
        ao = resp.headers.get("access-control-allow-origin")
        ac = resp.headers.get("access-control-allow-credentials")
        risks: List[str] = []
        if ao == "*" and ac and ac.lower() == "true":
            risks.append("Wildcard allow-origin with credentials can expose user data")
        rec: Optional[str] = None
        if not ao:
            rec = "Set strict CORS only if cross-origin is required"
        return CORSAssessment(url=str(resp.url), allow_origin=ao, allow_credentials=(ac.lower()=="true") if ac else None, risks=risks, recommendation=rec)
    except Exception:
        return CORSAssessment(url=url, allow_origin=None, allow_credentials=None, risks=[], recommendation=None)

