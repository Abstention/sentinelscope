from __future__ import annotations

from typing import List

import httpx

from sentinelscope.models import TakeoverAssessment, TakeoverFinding


SIGNATURES = [
    ("There isn't a GitHub Pages site here.", "GitHub Pages"),
    ("NoSuchBucket", "AWS S3"),
    ("The specified bucket does not exist", "AWS S3"),
    ("NoSuchDomain", "Azure"),
    ("Heroku | No such app", "Heroku"),
    ("There's nothing here, yet.", "Fastly/Netlify"),
]


async def check_takeover_candidates(subdomains: List[str], timeout: float = 5.0) -> TakeoverAssessment:
    flagged: List[TakeoverFinding] = []
    async with httpx.AsyncClient(follow_redirects=True, timeout=timeout) as client:
        for sub in subdomains[:200]:  # cap to avoid abuse
            try:
                resp = await client.get(f"http://{sub}")
                body = resp.text[:8000]
                for phrase, vendor in SIGNATURES:
                    if phrase in body:
                        flagged.append(TakeoverFinding(subdomain=sub, reason=f"Potential takeover signature: {vendor}"))
                        break
            except Exception:
                continue
    return TakeoverAssessment(checked_count=min(len(subdomains), 200), flagged=flagged)

