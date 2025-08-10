from __future__ import annotations

from datetime import datetime
from typing import List, Optional, Dict

from pydantic import BaseModel, Field


class DomainScanRequest(BaseModel):
    domain: str = Field(..., description="Domain to scan, e.g., example.com")
    scan_ports: bool = True
    scan_subdomains: bool = True
    analyze_headers: bool = True
    analyze_tls: bool = True
    analyze_dns: bool = True
    web_preview: bool = True
    analyze_cors: bool = True
    analyze_cookies: bool = True
    fingerprint_web: bool = True
    port_profile: str = Field(
        default="top30",
        description="One of: top30, top100, custom",
    )
    custom_ports: Optional[List[int]] = None


class PortResult(BaseModel):
    port: int
    is_open: bool


class PortScanResult(BaseModel):
    host: str
    ports_scanned: List[int]
    open_ports: List[int]
    results: List[PortResult]


class TLSInfo(BaseModel):
    domain: str
    port: int = 443
    valid_from: Optional[datetime] = None
    valid_to: Optional[datetime] = None
    days_until_expiry: Optional[int] = None
    subject: Optional[Dict[str, str]] = None
    issuer: Optional[Dict[str, str]] = None
    subject_alternative_names: List[str] = []
    protocol: Optional[str] = None
    warnings: List[str] = []


class HeaderFinding(BaseModel):
    header: str
    present: bool
    recommendation: Optional[str] = None


class SecurityHeadersAssessment(BaseModel):
    url: str
    findings: List[HeaderFinding]
    grade: str
    score: int = Field(..., ge=0, le=100)


class SubdomainsResult(BaseModel):
    root_domain: str
    discovered: List[str]
    sources: Dict[str, int]


class DomainScanResult(BaseModel):
    domain: str
    started_at: datetime
    finished_at: datetime
    subdomains: Optional[SubdomainsResult] = None
    ports: Optional[PortScanResult] = None
    tls: Optional[TLSInfo] = None
    headers: Optional[SecurityHeadersAssessment] = None
    dns: Optional["DNSAssessment"] = None
    preview: Optional["WebPreview"] = None
    takeover: Optional["TakeoverAssessment"] = None
    cors: Optional["CORSAssessment"] = None
    cookies: Optional["CookieAssessment"] = None
    web_fingerprint: Optional["WebFingerprint"] = None
    dns_axfr: Optional["DNSAxfrCheck"] = None


class DNSAssessment(BaseModel):
    domain: str
    a_records: List[str] = []
    aaaa_records: List[str] = []
    mx_records: List[str] = []
    txt_records: List[str] = []
    spf_present: bool = False
    spf_policy: Optional[str] = None  # e.g., -all, ~all, ?all
    spf_recommendation: Optional[str] = None
    dmarc_present: bool = False
    dmarc_policy: Optional[str] = None  # reject | quarantine | none
    dmarc_recommendation: Optional[str] = None


class WebPreview(BaseModel):
    url: str
    status_code: Optional[int] = None
    title: Optional[str] = None
    server: Optional[str] = None
    content_type: Optional[str] = None


class TakeoverFinding(BaseModel):
    subdomain: str
    reason: str


class TakeoverAssessment(BaseModel):
    checked_count: int
    flagged: List[TakeoverFinding]


class CORSAssessment(BaseModel):
    url: str
    allow_origin: Optional[str] = None
    allow_credentials: Optional[bool] = None
    risks: List[str] = []
    recommendation: Optional[str] = None


class CookieInfo(BaseModel):
    name: str
    secure: bool
    http_only: bool
    same_site: Optional[str] = None
    issues: List[str] = []


class CookieAssessment(BaseModel):
    url: str
    cookies: List[CookieInfo]


class WebFingerprint(BaseModel):
    url: str
    server: Optional[str] = None
    waf_or_cdn: Optional[str] = None
    technologies: List[str] = []


class DNSAxfrCheck(BaseModel):
    domain: str
    attempted_ns: List[str] = []
    axfr_allowed_on: List[str] = []

