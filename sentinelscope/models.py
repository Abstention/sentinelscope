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

