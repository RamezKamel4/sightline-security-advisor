"""
Banner and evidence extraction utilities for CVE correlation.
Only assign CVEs when there is concrete evidence of the product/service/version.
"""
import re
import requests
from typing import Dict, List, Optional, Any
from urllib.parse import urljoin

def extract_http_evidence(http_headers: Dict[str, str], body: str) -> Dict[str, Any]:
    """
    Extract product/version evidence from HTTP response.
    Returns dictionary with server_header, x_powered_by, html_title, body_tokens.
    """
    evidence = {}
    
    # Server header (most reliable)
    server = http_headers.get("server", "").strip()
    if server:
        evidence["server_header"] = server
    
    # X-Powered-By header
    x_powered = http_headers.get("x-powered-by", "").strip()
    if x_powered:
        evidence["x_powered_by"] = x_powered
    
    # HTML title
    title_match = re.search(r"<title>(.*?)</title>", body, re.IGNORECASE | re.DOTALL)
    if title_match:
        evidence["html_title"] = title_match.group(1).strip()
    
    # Search for vendor-specific tokens in body (first 8KB only to avoid false positives)
    body_sample = body[:8192].lower()
    vendor_tokens = ["tenda", "fritz", "avm", "tplink", "tp-link", "d-link", "netgear", 
                     "asus router", "ac18", "ac15", "miniupnpd", "libupnp"]
    found_tokens = []
    for token in vendor_tokens:
        if token in body_sample:
            found_tokens.append(token)
    if found_tokens:
        evidence["body_tokens"] = found_tokens
    
    return evidence

def extract_upnp_evidence(target: str) -> Dict[str, Any]:
    """
    Attempt to fetch UPnP device description XML and extract vendor/model info.
    Common paths: /rootDesc.xml, /description.xml, /device.xml
    """
    evidence = {}
    upnp_paths = ["/rootDesc.xml", "/description.xml", "/device.xml"]
    
    for path in upnp_paths:
        try:
            url = urljoin(f"http://{target}", path)
            response = requests.get(url, timeout=3, verify=False)
            if response.status_code == 200:
                xml_content = response.text.lower()
                
                # Extract modelName
                model_match = re.search(r"<modelname>(.*?)</modelname>", xml_content, re.IGNORECASE)
                if model_match:
                    evidence["upnp_model"] = model_match.group(1).strip()
                
                # Extract manufacturer
                mfr_match = re.search(r"<manufacturer>(.*?)</manufacturer>", xml_content, re.IGNORECASE)
                if mfr_match:
                    evidence["upnp_manufacturer"] = mfr_match.group(1).strip()
                
                # Extract modelDescription
                desc_match = re.search(r"<modeldescription>(.*?)</modeldescription>", xml_content, re.IGNORECASE)
                if desc_match:
                    evidence["upnp_description"] = desc_match.group(1).strip()
                
                break  # Found valid UPnP XML
        except Exception:
            continue
    
    return evidence

def banner_contains_product(banner_text: str, product_keywords: List[str]) -> bool:
    """
    Check if banner text contains any of the given product keywords (case-insensitive).
    """
    text = banner_text.lower()
    return any(k.lower() in text for k in product_keywords)

def check_endpoint_existence(target_url: str, path: str, timeout: int = 3) -> bool:
    """
    Check if a specific endpoint exists on target (non-destructive GET request).
    Returns True if endpoint responds with 200, 401, 403, or 302 (indicates it exists).
    """
    try:
        url = urljoin(target_url.rstrip('/'), path)
        response = requests.get(url, timeout=timeout, verify=False, allow_redirects=False)
        return response.status_code in (200, 401, 403, 302)
    except Exception:
        return False

def collect_http_evidence(target: str, port: int) -> Dict[str, Any]:
    """
    Collect evidence from an HTTP/HTTPS service.
    Returns combined evidence from headers, body, and UPnP device description.
    """
    evidence = {
        "reachable_paths": []
    }
    
    # Try HTTPS first, then HTTP
    for protocol in ["https", "http"]:
        try:
            url = f"{protocol}://{target}:{port}/"
            response = requests.get(url, timeout=5, verify=False, allow_redirects=True)
            
            # Extract from headers and body
            http_evidence = extract_http_evidence(dict(response.headers), response.text)
            evidence.update(http_evidence)
            
            # Check for known vulnerable endpoints (Tenda-specific)
            vulnerable_paths = ["/goform/SetUpnpCfg", "/goform/setUsbUnload", "/goform/setDeviceName"]
            for vpath in vulnerable_paths:
                if check_endpoint_existence(url, vpath):
                    evidence["reachable_paths"].append(vpath)
            
            break  # Successfully connected
        except Exception:
            continue
    
    # Try to get UPnP device description
    upnp_evidence = extract_upnp_evidence(target)
    evidence.update(upnp_evidence)
    
    return evidence

def extract_service_info(nmap_service: Dict[str, Any]) -> Dict[str, Any]:
    """
    Extract service information from Nmap scan result.
    Returns: service_name, banner, version, fingerprint_confidence, product
    """
    service_info = {
        "service_name": nmap_service.get("name", "unknown"),
        "banner": nmap_service.get("product", "") + " " + nmap_service.get("extrainfo", ""),
        "version": nmap_service.get("version", ""),
        "product": nmap_service.get("product", ""),
        "fingerprint_confidence": int(nmap_service.get("conf", 0))  # Nmap confidence 0-10
    }
    
    # Clean up banner
    service_info["banner"] = service_info["banner"].strip()
    
    return service_info
