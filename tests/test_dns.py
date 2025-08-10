from sentinelscope.scanning.dns_records import assess_dns


def test_dns_assessment_fields():
    res = assess_dns("example.com")
    assert res.domain == "example.com"
    assert isinstance(res.spf_present, bool)
    assert res.dmarc_policy in {None, "none", "quarantine", "reject"}

