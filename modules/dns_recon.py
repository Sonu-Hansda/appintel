import socket
import ssl
import requests
import dns.resolver
import dns.zone
import dns.query
from datetime import datetime, timezone
from typing import List, Set, Optional
from urllib.parse import urlparse

from models import ScanResult, Subdomain, DNSRecords, LiveHost
from utils import save_json

COMMON_SUBDOMAINS = [
    "www", "mail", "ftp", "localhost", "webmail", "smtp", "pop", "ns1", "webdisk",
    "ns2", "cpanel", "whm", "autodiscover", "autoconfig", "ns3", "m", "imap",
    "test", "ns", "blog", "pop3", "dev", "www2", "admin", "forum", "news",
    "vpn", "ns4", "www1", "imap4", "beta", "shop", "sql", "www3", "smtp2",
    "secure", "demo", "cp", "calendar", "wiki", "web1", "mail2", "img",
    "www4", "mysql", "beta2", "api", "cdn", "stats", "static", "staging",
    "www5", "mobile", "web2", "www.mail", "www.blog", "www.dev", "www.test",
    "www.shop", "www.forum", "www.news", "www.wiki", "www.api", "www.cdn",
    "app", "apps", "portal", "support", "help", "docs", "doc", "api-v1",
    "api-v2", "api-v3", "graphql", "rest", "swagger", "openapi", "health",
    "status", "monitor", "grafana", "prometheus", "kibana", "elastic",
    "search", "es", "db", "database", "redis", "mongo", "postgres", "mysql",
    "mariadb", "backup", "bak", "old", "v1", "v2", "v3", "alpha", "preprod",
    "prod", "production", "uat", "qa", "dev1", "dev2", "stage", "staging2",
    "git", "gitlab", "github", "svn", "jenkins", "ci", "cd", "build",
    "docker", "kube", "kubernetes", "k8s", "rancher", "consul", "vault",
    "nexus", "artifactory", "maven", "npm", "pypi", "registry",
    "admin", "administrator", "manage", "management", "manager",
    "login", "signin", "auth", "sso", "oauth", "saml", "ldap",
    "webmin", "plesk", "directadmin", "vesta", "cyberpanel",
    "phpmyadmin", "pma", "myadmin", "mysqladmin", "dbadmin",
    "roundcube", "squirrelmail", "horde", "zimbra", "exchange",
    "owa", "webmail2", "mail3", "smtp3", "mx", "mx1", "mx2",
    "ftp2", "sftp", "ssh", "telnet", "remote", "rdp", "vnc",
    "noc", "noc2", "netdata", "cacti", "nagios", "zabbix",
    "puppet", "ansible", "salt", "chef", "terraform",
    "s3", "s3-website", "bucket", "storage", "assets", "media",
    "files", "uploads", "download", "downloads", "dl",
    "js", "css", "images", "img", "static1", "static2",
    "edge", "fastly", "cloudfront", "akamai", "cdn1", "cdn2",
    "ads", "ad", "tracking", "analytics", "ga", "gtm",
    "chat", "livechat", "zendesk", "intercom", "crisp",
    "stripe", "paypal", "payment", "pay", "checkout",
    "webhook", "hooks", "callback", "redirect", "proxy",
    "internal", "intranet", "extranet", "private", "restricted",
    "confidential", "secret", "hidden", "temp", "tmp", "cache",
    "ws", "websocket", "socket", "io", "realtime", "push",
    "grpc", "rpc", "thrift", "soap", "xmlrpc", "jsonrpc"
]


def get_dns_records(domain: str) -> DNSRecords:
   
    print(f"[*] Querying DNS records for {domain}...")
    
    dns_records = DNSRecords()
    record_types = ['A', 'AAAA', 'MX', 'TXT', 'NS', 'CNAME']
    
    for record_type in record_types:
        try:
            answers = dns.resolver.resolve(domain, record_type)
            for answer in answers:
                value = str(answer)
                
                if record_type == 'A':
                    dns_records.A.append(value)
                elif record_type == 'AAAA':
                    dns_records.AAAA.append(value)
                elif record_type == 'MX':
                    # MX format: priority mailserver
                    dns_records.MX.append(value)
                elif record_type == 'TXT':
                    dns_records.TXT.append(value)
                elif record_type == 'NS':
                    dns_records.NS.append(value)
                elif record_type == 'CNAME':
                    dns_records.CNAME.append(value)
                    
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, 
                dns.resolver.NoNameservers, dns.exception.Timeout):
            continue
    
    print(f"[+] Found: {len(dns_records.A)} A, {len(dns_records.AAAA)} AAAA, "
          f"{len(dns_records.MX)} MX, {len(dns_records.TXT)} TXT, "
          f"{len(dns_records.NS)} NS, {len(dns_records.CNAME)} CNAME")
    
    return dns_records


def resolve_hostname(hostname: str) -> Optional[str]:
    
    try:
        return socket.gethostbyname(hostname)
    except socket.gaierror:
        return None


def brute_force_subdomains(domain: str, wordlist: List[str] = None) -> List[Subdomain]:
    
    print(f"[*] Brute forcing subdomains for {domain}...")
    
    wordlist = wordlist or COMMON_SUBDOMAINS
    found: List[Subdomain] = []
    checked: Set[str] = set()
    
    for word in wordlist:
        subdomain = f"{word}.{domain}"
        
        if subdomain in checked:
            continue
        checked.add(subdomain)
        
        ip = resolve_hostname(subdomain)
        if ip:
            found.append(Subdomain(
                name=subdomain,
                ip=ip,
                source="dns_brute"
            ))
    
    www_domain = f"www.{domain}"
    if www_domain not in checked:
        ip = resolve_hostname(www_domain)
        if ip:
            found.append(Subdomain(
                name=www_domain,
                ip=ip,
                source="dns_brute"
            ))
    
    print(f"[+] Found {len(found)} subdomains via brute force")
    return found


def get_certificate_subdomains(domain: str) -> List[Subdomain]:
   
    print(f"[*] Checking SSL certificate for {domain}...")
    
    found: List[Subdomain] = []
    
    try:
        context = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=10) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                sans = cert.get('subjectAltName', [])
                
                for san_type, san_value in sans:
                    if san_type == 'DNS' and san_value.endswith(domain):
                        if san_value != domain and san_value not in [s.name for s in found]:
                            ip = resolve_hostname(san_value)
                            if ip:
                                found.append(Subdomain(
                                    name=san_value,
                                    ip=ip,
                                    source="ssl_cert"
                                ))
        
        print(f"[+] Found {len(found)} subdomains in SSL certificate")
        
    except (socket.timeout, socket.gaierror, ssl.SSLError, ConnectionRefusedError) as e:
        print(f"[!] SSL certificate check failed: {e}")
    
    return found


def probe_http_host(url: str, timeout: int = 10) -> Optional[LiveHost]:
   
    try:
        response = requests.get(
            url,
            timeout=timeout,
            allow_redirects=True,
            headers={
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.0'
            },
            verify=False
        )
        
        title = None
        if '<title>' in response.text:
            start = response.text.find('<title>') + 7
            end = response.text.find('</title>', start)
            if end > start:
                title = response.text[start:end].strip()
        
        parsed = urlparse(url)
        ip = resolve_hostname(parsed.hostname)
        
        return LiveHost(
            url=url,
            status_code=response.status_code,
            title=title,
            ip=ip
        )
        
    except requests.RequestException:
        return None


def probe_hosts(hosts: List[str]) -> List[LiveHost]:
    
    print(f"[*] Probing {len(hosts)} hosts for HTTP/HTTPS...")
    
    live_hosts: List[LiveHost] = []
    urls_to_check = []
    
    for host in hosts:
        urls_to_check.append(f"https://{host}")
        urls_to_check.append(f"http://{host}")
    
    for url in urls_to_check:
        result = probe_http_host(url)
        if result and result.status_code < 500:
            existing = [h for h in live_hosts if h.url.replace('https://', '').replace('http://', '') 
                       == url.replace('https://', '').replace('http://', '')]
            if not existing:
                live_hosts.append(result)
                print(f"  [+] {url} -> {result.status_code} ({result.title or 'No title'})")
    
    print(f"[+] Found {len(live_hosts)} live hosts")
    return live_hosts


def save_scan_result(result: ScanResult, output_dir: str = "output") -> None:
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    filepath = f"{output_dir}/weblens_{result.target}_{timestamp}.json"
    save_json(result, filepath)


def run_dns_recon(domain: str, output_dir: str = "output",
                  wordlist: List[str] = None,
                  save_output: bool = True) -> ScanResult:
    
    print(f"\n{'='*50}")
    print(f"AppIntel : DNS Reconnaissance")
    print(f"Target: {domain}")
    print(f"{'='*50}\n")
    
    dns_records = get_dns_records(domain)
    
    subdomains = brute_force_subdomains(domain, wordlist)
    
    cert_subs = get_certificate_subdomains(domain)
    
    seen = set()
    all_subdomains = []
    for sub in subdomains + cert_subs:
        if sub.name not in seen:
            seen.add(sub.name)
            all_subdomains.append(sub)
    
    hosts_to_probe = [domain] + [s.name for s in all_subdomains]
    live_hosts = probe_hosts(hosts_to_probe)
    
    result = ScanResult(
        target=domain,
        subdomains=all_subdomains,
        dns_records=dns_records,
        live_hosts=live_hosts
    )
    
    if save_output:
        save_scan_result(result, output_dir)
    
    print(f"\n{'='*50}")
    print(f"Scan Complete")
    print(f"{'='*50}")
    
    return result