import socket
import ssl
import requests
from typing import Dict, Any, List
import traceback
from datetime import datetime

def probe_http_service(host: str, port: int, use_https: bool = False) -> Dict[str, Any]:
    """
    Probe HTTP/HTTPS service to gather headers, detect reverse proxies, and get detailed info.
    
    Returns:
        Dictionary containing headers, server info, proxy detection, and confidence score
    """
    result = {
        'headers': {},
        'tls_info': {},
        'raw_banner': '',
        'proxy_detection': {},
        'detection_methods': [],
        'confidence': 0.0,
        'technologies': []
    }
    
    protocol = 'https' if use_https or port in [443, 8443] else 'http'
    url = f"{protocol}://{host}:{port}"
    
    try:
        # Attempt HTTP HEAD request first (faster)
        print(f"🔍 Probing {url} with HEAD request...")
        response = requests.head(url, timeout=5, verify=False, allow_redirects=True)
        result['headers'] = dict(response.headers)
        result['detection_methods'].append('http_head')
        result['confidence'] += 25
        
        # Also try GET for more information
        print(f"🔍 Probing {url} with GET request...")
        response_get = requests.get(url, timeout=5, verify=False, allow_redirects=True)
        if response_get.headers:
            result['headers'].update(dict(response_get.headers))
            result['raw_banner'] = response_get.text[:500] if response_get.text else ''
            result['detection_methods'].append('http_get')
            result['confidence'] += 15
        
        # Analyze headers for server technology
        server_header = response.headers.get('Server', '').lower()
        x_powered_by = response.headers.get('X-Powered-By', '').lower()
        
        technologies = []
        confidence_boost = 0
        
        # Detect OpenResty
        if 'openresty' in server_header:
            technologies.append({
                'name': 'OpenResty',
                'version': extract_version(server_header, 'openresty'),
                'role': 'web-server',
                'confidence': 95
            })
            confidence_boost += 30
            
        # Detect nginx
        if 'nginx' in server_header and 'openresty' not in server_header:
            technologies.append({
                'name': 'nginx',
                'version': extract_version(server_header, 'nginx'),
                'role': 'web-server',
                'confidence': 90
            })
            confidence_boost += 30
            
        # Detect Apache
        if 'apache' in server_header:
            technologies.append({
                'name': 'Apache',
                'version': extract_version(server_header, 'apache'),
                'role': 'web-server',
                'confidence': 90
            })
            confidence_boost += 30
            
        # Detect reverse proxies and CDNs
        proxy_indicators = detect_reverse_proxy(result['headers'])
        if proxy_indicators:
            result['proxy_detection'] = proxy_indicators
            result['detection_methods'].append('proxy_detection')
            confidence_boost += 20
            
            # If reverse proxy detected, backend might be different
            if proxy_indicators.get('detected'):
                # Add front-end technology
                if technologies:
                    technologies[0]['role'] = 'reverse-proxy/front-end'
                
                # Check X-Powered-By for backend
                if x_powered_by:
                    backend_tech = {
                        'name': x_powered_by,
                        'version': 'unknown',
                        'role': 'backend',
                        'confidence': 60
                    }
                    technologies.append(backend_tech)
        
        result['technologies'] = technologies
        result['confidence'] = min(result['confidence'] + confidence_boost, 100.0)
        
        # TLS/SSL information for HTTPS
        if protocol == 'https':
            tls_data = get_tls_info(host, port)
            if tls_data:
                result['tls_info'] = tls_data
                result['detection_methods'].append('tls_probe')
                result['confidence'] += 10
        
    except requests.exceptions.SSLError as e:
        print(f"⚠️ SSL error probing {url}: {e}")
        result['detection_methods'].append('http_probe_failed_ssl')
        # Try without SSL verification
        try:
            response = requests.head(url, timeout=5, verify=False)
            result['headers'] = dict(response.headers)
            result['confidence'] = 40
        except:
            pass
    except requests.exceptions.Timeout:
        print(f"⏰ Timeout probing {url}")
        result['detection_methods'].append('http_probe_timeout')
    except Exception as e:
        print(f"❌ Error probing {url}: {e}")
        result['detection_methods'].append('http_probe_failed')
        
    return result


def detect_reverse_proxy(headers: Dict[str, str]) -> Dict[str, Any]:
    """
    Detect reverse proxy or CDN based on HTTP headers.
    
    Returns:
        Dictionary with proxy detection information
    """
    proxy_info = {
        'detected': False,
        'type': None,
        'indicators': [],
        'provider': None
    }
    
    headers_lower = {k.lower(): v for k, v in headers.items()}
    
    # Check for common proxy headers
    proxy_headers = [
        'via', 'x-forwarded-for', 'x-forwarded-proto', 'x-forwarded-host',
        'x-real-ip', 'x-proxy-id', 'forwarded'
    ]
    
    for header in proxy_headers:
        if header in headers_lower:
            proxy_info['detected'] = True
            proxy_info['indicators'].append(f"{header}: {headers_lower[header]}")
    
    # Detect specific CDN/proxy providers
    if 'cf-ray' in headers_lower or 'cf-cache-status' in headers_lower:
        proxy_info['provider'] = 'Cloudflare'
        proxy_info['type'] = 'CDN'
        proxy_info['detected'] = True
        
    if 'x-amz-cf-id' in headers_lower or 'x-amz-request-id' in headers_lower:
        proxy_info['provider'] = 'Amazon CloudFront'
        proxy_info['type'] = 'CDN'
        proxy_info['detected'] = True
        
    if 'x-azure-ref' in headers_lower:
        proxy_info['provider'] = 'Azure Front Door'
        proxy_info['type'] = 'CDN'
        proxy_info['detected'] = True
        
    if 'x-fastly-request-id' in headers_lower:
        proxy_info['provider'] = 'Fastly'
        proxy_info['type'] = 'CDN'
        proxy_info['detected'] = True
        
    if 'x-varnish' in headers_lower:
        proxy_info['provider'] = 'Varnish'
        proxy_info['type'] = 'Cache/Reverse Proxy'
        proxy_info['detected'] = True
    
    # Check server header for proxy software
    server = headers_lower.get('server', '').lower()
    if 'varnish' in server:
        proxy_info['provider'] = 'Varnish'
        proxy_info['type'] = 'Cache/Reverse Proxy'
        proxy_info['detected'] = True
    if 'nginx' in server or 'openresty' in server:
        # Nginx/OpenResty often used as reverse proxy
        if 'via' in headers_lower or 'x-forwarded-for' in headers_lower:
            proxy_info['type'] = 'Reverse Proxy'
            if not proxy_info['provider']:
                proxy_info['provider'] = 'nginx/OpenResty'
    
    return proxy_info


def get_tls_info(host: str, port: int) -> Dict[str, Any]:
    """
    Get TLS/SSL certificate information.
    
    Returns:
        Dictionary with TLS certificate details
    """
    tls_info = {}
    
    try:
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        
        with socket.create_connection((host, port), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()
                
                if cert:
                    tls_info['version'] = ssock.version()
                    tls_info['cipher'] = ssock.cipher()[0] if ssock.cipher() else None
                    
                    # Certificate details
                    tls_info['subject'] = dict(x[0] for x in cert.get('subject', []))
                    tls_info['issuer'] = dict(x[0] for x in cert.get('issuer', []))
                    tls_info['serial_number'] = cert.get('serialNumber')
                    tls_info['not_before'] = cert.get('notBefore')
                    tls_info['not_after'] = cert.get('notAfter')
                    tls_info['san'] = cert.get('subjectAltName', [])
                    
                    # Detect CDN by certificate issuer
                    issuer_org = tls_info['issuer'].get('organizationName', '').lower()
                    if 'cloudflare' in issuer_org:
                        tls_info['cdn_detected'] = 'Cloudflare'
                    elif 'amazon' in issuer_org or 'aws' in issuer_org:
                        tls_info['cdn_detected'] = 'Amazon CloudFront'
                    elif 'google' in issuer_org:
                        tls_info['cdn_detected'] = 'Google Cloud CDN'
                    
                print(f"🔒 TLS info captured for {host}:{port}")
    except Exception as e:
        print(f"⚠️ Could not get TLS info for {host}:{port}: {e}")
        
    return tls_info


def probe_banner(host: str, port: int, timeout: int = 5) -> str:
    """
    Grab service banner using raw socket connection.
    
    Returns:
        Raw banner string
    """
    banner = ''
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((host, port))
        
        # Try to get banner
        banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
        sock.close()
        
        print(f"📡 Banner grabbed from {host}:{port}: {banner[:100]}...")
    except Exception as e:
        print(f"⚠️ Could not grab banner from {host}:{port}: {e}")
        
    return banner


def extract_version(text: str, software: str) -> str:
    """
    Extract version number from server header or text.
    
    Returns:
        Version string or 'unknown'
    """
    import re
    
    # Pattern to match version numbers (e.g., 1.27.1.1, 2.4.41)
    pattern = rf'{software}[/\s]+(\d+(?:\.\d+)*)'
    match = re.search(pattern, text, re.IGNORECASE)
    
    if match:
        return match.group(1)
    
    return 'unknown'


def calculate_confidence(nmap_version: str, probe_data: Dict[str, Any]) -> float:
    """
    Calculate overall confidence score based on nmap results and probe data.
    
    Returns:
        Confidence score (0-100)
    """
    confidence = 0.0
    
    # Base confidence from nmap
    if nmap_version and nmap_version.lower() != 'unknown':
        confidence += 40
    else:
        confidence += 10
    
    # Boost from HTTP probes
    if probe_data.get('headers'):
        confidence += 25
        
        # Extra boost if server header is present
        if probe_data['headers'].get('Server'):
            confidence += 15
    
    # Boost from TLS info
    if probe_data.get('tls_info'):
        confidence += 10
    
    # Boost from banner grab
    if probe_data.get('raw_banner'):
        confidence += 10
    
    return min(confidence, 100.0)


def merge_detection_results(nmap_service: str, nmap_version: str, probe_data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Merge nmap results with probe data to create comprehensive detection result.
    
    Returns:
        Merged detection result with technologies, confidence, and all metadata
    """
    result = {
        'nmap_service': nmap_service,
        'nmap_version': nmap_version,
        'technologies': probe_data.get('technologies', []),
        'confidence': probe_data.get('confidence', 0),
        'headers': probe_data.get('headers', {}),
        'tls_info': probe_data.get('tls_info', {}),
        'raw_banner': probe_data.get('raw_banner', ''),
        'proxy_detection': probe_data.get('proxy_detection', {}),
        'detection_methods': probe_data.get('detection_methods', []),
        'conflicts': []
    }
    
    # Add nmap as detection method
    result['detection_methods'].append('nmap')
    
    # Check for conflicts between nmap and HTTP probe
    if probe_data.get('technologies'):
        nmap_lower = nmap_service.lower()
        for tech in probe_data['technologies']:
            tech_lower = tech['name'].lower()
            
            # Check if technologies conflict
            if nmap_lower and tech_lower and nmap_lower not in tech_lower and tech_lower not in nmap_lower:
                # Possible conflict - add both
                result['conflicts'].append({
                    'nmap': f"{nmap_service} {nmap_version}",
                    'http_probe': f"{tech['name']} {tech.get('version', 'unknown')}",
                    'explanation': f"nmap detected '{nmap_service}' but HTTP probe found '{tech['name']}' - likely reverse proxy setup"
                })
    
    # Recalculate confidence based on merged data
    result['confidence'] = calculate_confidence(nmap_version, probe_data)
    
    # If low confidence, flag for follow-up
    result['needs_followup'] = result['confidence'] < 70
    
    return result
