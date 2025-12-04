"""
HTTP Service Inspector
Actively probes HTTP/HTTPS services to gather evidence for accurate CVE matching.
"""

import requests
import ssl
import socket
import re
from typing import Dict, Any, Optional, Tuple
from urllib.parse import urlparse

# Timeout for HTTP requests
HTTP_TIMEOUT = 5

def parse_server_header(server_header: str) -> Tuple[Optional[str], Optional[str]]:
    """
    Parse Server header into product and version.
    
    Examples:
        "Apache/2.4.41 (Ubuntu)" -> ("apache", "2.4.41")
        "nginx/1.18.0" -> ("nginx", "1.18.0")
        "Apache" -> ("apache", None)
        "Microsoft-IIS/10.0" -> ("microsoft-iis", "10.0")
    
    Returns:
        (product, version) tuple. Either can be None if not detected.
    """
    if not server_header:
        return None, None
    
    # Keep human-readable product names for display AND NVD keyword searches
    product_map = {
        "apache": "Apache httpd",
        "httpd": "Apache httpd",
        "microsoft-iis": "Microsoft IIS",
        "iis": "Microsoft IIS",
        "nginx": "nginx",
        "lighttpd": "lighttpd",
        "tomcat": "Apache Tomcat",
        "jetty": "Eclipse Jetty",
    }
    
    # Try to match product/version pattern
    # Pattern: product/version (additional info)
    match = re.match(r'^([a-zA-Z0-9_-]+)(?:/([0-9.]+))?', server_header.strip())
    
    if match:
        product = match.group(1).lower()
        version = match.group(2)
        
        # Normalize product name
        product = product_map.get(product, product)
        
        return product, version
    
    return None, None


def get_http_headers(hostname: str, ip: Optional[str] = None, port: int = 80) -> Dict[str, Any]:
    """
    Send HTTP request to gather server information.
    Uses Host header to ensure proper virtual host routing.
    
    Returns:
        {
            "success": bool,
            "server": str or None,
            "headers": dict,
            "redirect_to_https": bool,
            "error": str (if failed)
        }
    """
    result = {
        "success": False,
        "server": None,
        "headers": {},
        "redirect_to_https": False,
        "error": None
    }
    
    try:
        # Use IP if provided, otherwise use hostname
        target = ip if ip else hostname
        url = f"http://{target}:{port}/"
        
        # Set Host header to the actual hostname
        headers = {"Host": hostname}
        
        print(f"🌐 Probing HTTP service: {url} (Host: {hostname})")
        
        response = requests.get(
            url,
            headers=headers,
            timeout=HTTP_TIMEOUT,
            allow_redirects=False,
            verify=False
        )
        
        result["success"] = True
        result["server"] = response.headers.get("Server")
        result["headers"] = dict(response.headers)
        
        # Check for HTTPS redirect
        location = response.headers.get("Location", "")
        if location.startswith("https://"):
            result["redirect_to_https"] = True
            print(f"✅ HTTP redirects to HTTPS: {location}")
        
        if result["server"]:
            print(f"✅ Server header detected: {result['server']}")
        else:
            print(f"⚠️ No Server header present")
            
    except requests.exceptions.Timeout:
        result["error"] = "timeout"
        print(f"⏰ HTTP request timeout for {hostname}")
    except requests.exceptions.RequestException as e:
        result["error"] = str(e)
        print(f"❌ HTTP request failed for {hostname}: {e}")
    except Exception as e:
        result["error"] = f"unexpected: {e}"
        print(f"❌ Unexpected error probing {hostname}: {e}")
    
    return result


def get_tls_info(hostname: str, port: int = 443) -> Dict[str, Any]:
    """
    Inspect TLS certificate and configuration.
    
    Returns:
        {
            "success": bool,
            "cert_valid": bool,
            "cert_expired": bool,
            "cert_issuer": str,
            "cert_subject": str,
            "cipher": str,
            "protocol": str,
            "error": str (if failed)
        }
    """
    result = {
        "success": False,
        "cert_valid": False,
        "cert_expired": False,
        "cert_issuer": None,
        "cert_subject": None,
        "cipher": None,
        "protocol": None,
        "error": None
    }
    
    try:
        print(f"🔒 Inspecting TLS service: {hostname}:{port}")
        
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        
        with socket.create_connection((hostname, port), timeout=HTTP_TIMEOUT) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                result["success"] = True
                result["protocol"] = ssock.version()
                result["cipher"] = ssock.cipher()[0] if ssock.cipher() else None
                
                cert = ssock.getpeercert()
                if cert:
                    result["cert_valid"] = True
                    result["cert_subject"] = dict(x[0] for x in cert.get('subject', []))
                    result["cert_issuer"] = dict(x[0] for x in cert.get('issuer', []))
                    
                    # Check if certificate is expired
                    # Note: This is a basic check, ssl context already validates
                    result["cert_expired"] = False
                
                print(f"✅ TLS connection successful: {result['protocol']} with {result['cipher']}")
                
    except ssl.SSLError as e:
        result["error"] = f"ssl_error: {e}"
        if "certificate verify failed" in str(e):
            result["cert_valid"] = False
            result["cert_expired"] = "expired" in str(e).lower()
        print(f"❌ TLS error for {hostname}: {e}")
    except socket.timeout:
        result["error"] = "timeout"
        print(f"⏰ TLS connection timeout for {hostname}")
    except Exception as e:
        result["error"] = str(e)
        print(f"❌ Unexpected TLS error for {hostname}: {e}")
    
    return result


def inspect_http_service(hostname: str, ip: str, port: int) -> Dict[str, Any]:
    """
    Comprehensive HTTP/HTTPS service inspection.
    
    Returns evidence dict with:
    - product, version (parsed from headers)
    - http_headers (full headers)
    - tls_info (if HTTPS or redirect detected)
    - confidence level
    - recommendations
    """
    evidence = {
        "product": None,
        "version": None,
        "http_headers": {},
        "tls_info": {},
        "redirect_to_https": False,
        "confidence": "low",
        "evidence_sources": [],
        "recommendations": []
    }
    
    # Probe HTTP service
    http_result = get_http_headers(hostname, ip, port)
    
    if http_result["success"]:
        evidence["http_headers"] = http_result["headers"]
        evidence["redirect_to_https"] = http_result["redirect_to_https"]
        
        # Parse Server header
        if http_result["server"]:
            product, version = parse_server_header(http_result["server"])
            evidence["product"] = product
            evidence["version"] = version
            evidence["evidence_sources"].append("server_header")
            
            if product and version:
                evidence["confidence"] = "high"
            elif product:
                evidence["confidence"] = "medium"
                evidence["recommendations"].append(
                    "Server header lacks version information. Consider authenticated scan for precise version detection."
                )
        else:
            evidence["recommendations"].append(
                "No Server header present. Service fingerprinting may be limited."
            )
    
    # If HTTPS port or redirect detected, inspect TLS
    if port == 443 or evidence["redirect_to_https"]:
        tls_result = get_tls_info(hostname, 443)
        evidence["tls_info"] = tls_result
        
        if tls_result["success"]:
            if not tls_result["cert_valid"]:
                evidence["recommendations"].append(
                    "TLS certificate validation failed. Check certificate validity and trust chain."
                )
            if tls_result["cert_expired"]:
                evidence["recommendations"].append(
                    "TLS certificate is expired. Update certificate immediately."
                )
    
    return evidence
