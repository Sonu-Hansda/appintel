from typing import Any, Dict, List, Optional

import requests
from bs4 import BeautifulSoup

from models import TechStack, DetectedTechnology
from signatures.tech_signatures import TECH_SIGNATURES


def fetch_page(url: str) -> Optional[Dict[str, Any]]:
    try:
        response = requests.get(
            url,
            timeout=10,
            allow_redirects=True,
            headers={
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
            }
        )
        soup = BeautifulSoup(response.text, 'html.parser')
        scripts: List[str] = []
        for script in soup.find_all('script', src=True):
            scripts.append(script['src'])

        return {
            'headers': dict(response.headers),
            'html': response.text.lower(),
            'scripts': ' '.join(scripts).lower(),
            'cookies': response.headers.get('Set-Cookie', '').lower()
        }
    except requests.RequestException as e:
        print(f"[!] Failed to fetch {url}: {e}")
        return None


def check_signatures(
    page_data: Dict[str, Any],
    tech_name: str,
    tech_info: Dict[str, Any]
) -> Optional[DetectedTechnology]:
    evidence = []
    methods = tech_info.get('methods', [])
    signatures = tech_info.get('signatures', {})
    
    if 'header' in methods and 'header' in signatures:
        header_text = ' '.join([f"{k}: {v}" for k, v in page_data['headers'].items()])
        header_text = header_text.lower()
        for sig in signatures['header']:
            if sig.lower() in header_text:
                evidence.append(f"Header: {sig}")
    
    if 'html' in methods and 'html' in signatures:
        for sig in signatures['html']:
            if sig.lower() in page_data['html']:
                evidence.append(f"HTML: {sig}")
    
    if 'script' in methods and 'script' in signatures:
        for sig in signatures['script']:
            if sig.lower() in page_data['scripts']:
                evidence.append(f"Script: {sig}")
    
    if 'cookie' in methods and 'cookie' in signatures:
        for sig in signatures['cookie']:
            if sig.lower() in page_data['cookies']:
                evidence.append(f"Cookie: {sig}")
    
    if evidence:
        confidence = "high" if len(evidence) >= 2 else "medium"
        return DetectedTechnology(
            name=tech_name,
            category=tech_info['category'],
            confidence=confidence,
            evidence=evidence,
            icon=tech_info.get('icon', '🔧')
        )
    
    return None


def analyze_url(url: str) -> TechStack:
    print(f"\n[*] Analyzing: {url}")

    page_data = fetch_page(url)
    if not page_data:
        return TechStack(url=url)
    
    detected = []
    for tech_name, tech_info in TECH_SIGNATURES.items():
        result = check_signatures(page_data, tech_name, tech_info)
        if result:
            detected.append(result)
            print(f"  [+] {tech_name} ({result.confidence})")
    
    print(f"[+] Found {len(detected)} technologies")
    
    return TechStack(
        url=url,
        detected=detected
    )