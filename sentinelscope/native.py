from __future__ import annotations

try:
    # The Rust extension module, if built via maturin
    import sentinelscope_rs  # type: ignore

    def scan_ports_native(host: str, ports: list[int], timeout_ms: int, concurrency: int) -> list[tuple[int, bool]]:
        return sentinelscope_rs.scan_ports(host, ports, timeout_ms, concurrency)

    def scan_ports_native_available() -> bool:
        return True

except Exception:  # noqa: BLE001
    def scan_ports_native(host: str, ports: list[int], timeout_ms: int, concurrency: int) -> list[tuple[int, bool]]:  # type: ignore[no-redef]
        raise RuntimeError("Native extension not available")

    def scan_ports_native_available() -> bool:  # type: ignore[no-redef]
        return False

