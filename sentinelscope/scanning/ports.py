from __future__ import annotations

import asyncio
from typing import Iterable, List

from sentinelscope.models import PortResult, PortScanResult


TOP_30_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139,
    143, 443, 445, 993, 995, 1723, 3306, 3389, 5900, 8080,
    8443, 8000, 6379, 27017, 5432, 1521, 5000, 11211, 9200, 25565,
]


async def _try_connect(host: str, port: int, timeout: float = 1.0) -> bool:
    try:
        reader, writer = await asyncio.wait_for(asyncio.open_connection(host, port), timeout)
        writer.close()
        await writer.wait_closed()
        return True
    except (asyncio.TimeoutError, OSError):
        return False


async def scan_ports(host: str, ports: Iterable[int], concurrency: int = 200, timeout: float = 1.0) -> PortScanResult:
    ports_list: List[int] = sorted(set(int(p) for p in ports))
    semaphore = asyncio.Semaphore(concurrency)

    async def scan_one(p: int) -> PortResult:
        async with semaphore:
            is_open = await _try_connect(host, p, timeout=timeout)
            return PortResult(port=p, is_open=is_open)

    results = await asyncio.gather(*(scan_one(p) for p in ports_list))
    open_ports = [r.port for r in results if r.is_open]
    return PortScanResult(host=host, ports_scanned=ports_list, open_ports=open_ports, results=results)

