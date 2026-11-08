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

class ScanResult(BaseModel):
    target: str
    scan_time: datetime = Field(default_factory=datetime.now)
    subdomains: List[Subdomain] = []
    dns_records: DNSRecords = Field(default_factory=DNSRecords)
    live_hosts: List[LiveHost] = []