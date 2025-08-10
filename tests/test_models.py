from datetime import datetime, timedelta

from sentinelscope.models import DomainScanResult, TLSInfo


def test_model_serialization_roundtrip():
    tls = TLSInfo(
        domain="example.com",
        valid_from=datetime.utcnow() - timedelta(days=10),
        valid_to=datetime.utcnow() + timedelta(days=20),
        subject={"CN": "example.com"},
        issuer={"CN": "Test CA"},
        subject_alternative_names=["example.com", "www.example.com"],
        protocol="TLSv1.3",
    )
    res = DomainScanResult(
        domain="example.com",
        started_at=datetime.utcnow(),
        finished_at=datetime.utcnow(),
        tls=tls,
    )
    payload = res.model_dump_json()
    assert "example.com" in payload

