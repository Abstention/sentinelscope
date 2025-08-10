import asyncio

from sentinelscope.scanning.web_preview import fetch_preview


def test_web_preview_returns_fields():
    async def _run():
        res = await fetch_preview("https://example.com")
        assert res.url == "https://example.com"
        assert res.status_code is not None
    asyncio.run(_run())

