from datetime import datetime
from typing import List, Optional
from pydantic import BaseModel, Field

class Subdomain(BaseModel):
    name: str
    ip: Optional[str] = None
    source: str = "subfinder"

class DNSRecords(BaseModel):
    A: List[str] = []
    AAAA: List[str] = []
    MX: List[str] = []
    TXT: List[str] = []
    NS: List[str] = []
    CNAME: List[str] = []

class LiveHost(BaseModel):
    url: str
    status_code: int
    title: Optional[str] = None
    ip: Optional[str] = None

class DetectedTechnology(BaseModel):
    name: str
    category: str
    confidence: str = "medium"
    evidence: List[str] = Field(default_factory=list)
    icon: str = "🔧"

class TechStack(BaseModel):
    url: str
    detected: List[DetectedTechnology] = Field(default_factory=list)

class ScanResult(BaseModel):
    target: str
    scan_time: datetime = Field(default_factory=datetime.now)
    subdomains: List[Subdomain] = Field(default_factory=list)
    dns_records: DNSRecords = Field(default_factory=DNSRecords)
    live_hosts: List[LiveHost] = Field(default_factory=list)
    technologies: List[TechStack] = Field(default_factory=list)