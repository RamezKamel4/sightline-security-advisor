import requests
import traceback
import os
import re
from typing import List, Dict, Any
from supabase import create_client, Client

# 🚀 Supabase connection - read from environment variables
SUPABASE_URL = os.getenv("SUPABASE_URL")
SUPABASE_KEY = os.getenv("SUPABASE_SERVICE_ROLE_KEY")

# Only create client if credentials are available
supabase: Client = None
if SUPABASE_URL and SUPABASE_KEY:
    try:
        supabase = create_client(SUPABASE_URL, SUPABASE_KEY)
        print("✅ Supabase client initialized for CVE storage")
    except Exception as e:
        print(f"⚠️ Failed to initialize Supabase client: {e}")
else:
    print("⚠️ Supabase credentials not found - CVE storage disabled")

# Keywords that should exclude CVEs from PC/server reports
EXCLUDED_KEYWORDS = [
    "router", "firmware", "tenda", "tp-link", "weblogic", "cisco", "d-link",
    "zyxel", "iot", "camera", "modem", "printer", "netgear", "linksys",
    "buffalo", "asus router", "belkin", "huawei router", "wireless router",
    "broadband router", "access point", "wrt54g", "fritzbox router firmware",
    "ac18", "ac15", "ac1200", "kernel 1.0", "kernel 2.0", "kernel 2.2",
    "embedded device", "smart tv", "set-top box", "dvr"
]

# Router vendor exclusion list for cross-contamination prevention
EXCLUDED_VENDORS = ["tenda", "tp-link", "d-link", "zyxel", "asus router", "netgear", "linksys", "buffalo", "belkin"]

# Known service to vendor mapping
SERVICE_VENDOR_MAP = {
    "FRITZ!Box http config": "AVM FRITZ!Box",
    "FRITZ!OS": "AVM FRITZ!Box",
    "Tenda http config": "Tenda",
    "TP-Link router http": "TP-Link",
    "D-Link router admin": "D-Link",
    "Netgear genie": "Netgear"
}

def detect_vendor(service_name: str, version: str) -> str:
    """
    Detect vendor/product name from service info.
    """
    combined = f"{service_name} {version}".lower()
    
    # Check known service map first
    if service_name in SERVICE_VENDOR_MAP:
        return SERVICE_VENDOR_MAP[service_name]
    
    # Pattern matching
    if "fritz" in combined or "avm" in combined:
        return "AVM FRITZ!Box"
    elif "tenda" in combined:
        return "Tenda"
    elif "tp-link" in combined:
        return "TP-Link"
    elif "d-link" in combined:
        return "D-Link"
    elif "netgear" in combined:
        return "Netgear"
    elif "asus" in combined and "router" in combined:
        return "ASUS"
    elif "cisco" in combined:
        return "Cisco"
    elif "zyxel" in combined:
        return "Zyxel"
    
    return "Generic"

def filter_cves_by_vendor(cve_results: List[Dict[str, Any]], product_name: str) -> List[Dict[str, Any]]:
    """
    Filter CVEs to only include those matching the detected vendor/product.
    For Generic products, still filter out known router vendors.
    """
    product = product_name.lower()
    filtered = []
    
    for cve in cve_results:
        text = (cve.get("title", "") + " " + cve.get("description", "")).lower()
        
        # For specific products, match the product name
        if product_name != "Generic":
            if product.lower().split()[0] in text:
                filtered.append(cve)
            # Include if no specific vendor mentioned (generic vulnerability)
            elif not any(vendor in text for vendor in EXCLUDED_VENDORS + ["cisco", "zyxel"]):
                filtered.append(cve)
        # For Generic products, exclude all router vendors
        else:
            if not any(vendor in text for vendor in EXCLUDED_VENDORS + ["cisco", "zyxel", "router", "firmware"]):
                filtered.append(cve)
    
    print(f"🔍 Vendor filter ({product_name}): {len(cve_results)} → {len(filtered)} CVEs")
    return filtered

def exclude_unrelated_router_cves(cve_results: List[Dict[str, Any]], product_name: str) -> List[Dict[str, Any]]:
    """
    Exclude CVEs from other router vendors.
    For Generic products, exclude ALL router vendor CVEs.
    """
    product = product_name.lower()
    filtered = []
    
    for cve in cve_results:
        text = (cve.get("title", "") + " " + cve.get("description", "")).lower()
        
        # Check for any router vendor mentions
        is_other_vendor = any(v in text for v in EXCLUDED_VENDORS + ["cisco", "zyxel"])
        
        if product_name == "Generic":
            # For unknown products, exclude ALL router CVEs
            if is_other_vendor:
                print(f"🚫 Excluded {cve['id']} - router vendor detected for generic service")
                continue
        else:
            # For specific products, only exclude if it's a different vendor
            is_our_vendor = any(part in text for part in product.split())
            if is_other_vendor and not is_our_vendor:
                print(f"🚫 Excluded {cve['id']} - different vendor detected")
                continue
        
        filtered.append(cve)
    
    print(f"🔍 Cross-vendor filter: {len(cve_results)} → {len(filtered)} CVEs")
    return filtered

def filter_cves_by_os(os_name: str, cve_results: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Filter CVEs based on detected OS type.
    """
    if not os_name or os_name.lower() == "unknown":
        return cve_results
    
    os_name = os_name.lower()
    filtered = []
    
    for cve in cve_results:
        desc = (cve.get("title", "") + " " + cve.get("description", "")).lower()
        
        # Windows-specific vulnerabilities
        if "windows" in os_name and any(k in desc for k in [
            "windows", "smb", "rdp", "rpc", "edge", "internet explorer",
            "microsoft", "active directory", "iis", "netbios"
        ]):
            filtered.append(cve)
        # Linux-specific vulnerabilities
        elif "linux" in os_name and any(k in desc for k in [
            "linux", "kernel", "ubuntu", "debian", "ssh", "apache", "nginx",
            "red hat", "centos", "fedora", "suse"
        ]):
            filtered.append(cve)
        # macOS-specific vulnerabilities
        elif "mac" in os_name or "darwin" in os_name and any(k in desc for k in [
            "macos", "mac os", "apple", "safari", "darwin"
        ]):
            filtered.append(cve)
        # Generic vulnerabilities (no specific OS keywords)
        elif not any(os_keyword in desc for os_keyword in [
            "windows", "linux", "mac", "macos", "darwin", "router", "firmware"
        ]):
            filtered.append(cve)
    
    print(f"🔍 OS filter ({os_name}): {len(cve_results)} → {len(filtered)} CVEs")
    return filtered

def exclude_unrelated_cves(cve_results: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Exclude CVEs with keywords that indicate they're not relevant to PC/server scans.
    """
    filtered = []
    for cve in cve_results:
        desc = (cve.get("title", "") + " " + cve.get("description", "")).lower()
        if not any(bad in desc for bad in EXCLUDED_KEYWORDS):
            filtered.append(cve)
        else:
            print(f"🚫 Excluded {cve['id']} - matched blacklist keyword")
    
    print(f"🔍 Keyword filter: {len(cve_results)} → {len(filtered)} CVEs")
    return filtered

def filter_by_age_and_score(cve_results: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Filter CVEs by publication year and CVSS score.
    """
    filtered = []
    for cve in cve_results:
        cve_id = cve.get("id", "")
        
        # Extract year from CVE ID (format: CVE-YYYY-XXXXX)
        year_match = re.search(r'CVE-(\d{4})-', cve_id)
        year = int(year_match.group(1)) if year_match else 0
        
        cvss_score = cve.get("cvss") or 0
        
        # Keep CVEs from 2020 onwards with CVSS >= 6.0 (stricter filter)
        # Older CVEs are less relevant for modern systems
        if year >= 2020 and cvss_score >= 6.0:
            filtered.append(cve)
        # Keep recent CVEs even without CVSS score (awaiting analysis)
        elif year >= 2024 and cvss_score == 0:
            print(f"⚠️ Including {cve_id} - recent CVE without score (awaiting analysis)")
            filtered.append(cve)
        elif year == 0 or cvss_score == 0:
            # If we can't determine year or score, be conservative and exclude
            print(f"🚫 Excluded {cve_id} - unknown year or score")
    
    print(f"🔍 Age/Score filter: {len(cve_results)} → {len(filtered)} CVEs")
    return filtered

def strict_match_cve_to_evidence(cve: dict, service_info: dict, evidence: dict) -> bool:
    """
    Return True only if there is direct evidence linking the CVE to the scanned service.
    
    service_info: {
        'service_name': 'upnp',
        'banner': 'miniupnpd/1.9',
        'version': '1.9',
        'product': 'miniupnpd',
        'fingerprint_confidence': 85
    }
    evidence: {
        'server_header': 'miniupnpd/1.9',
        'html_title': '...',
        'body_tokens': ['tenda', 'ac18'],
        'reachable_paths': ['/goform/SetUpnpCfg'],
        'upnp_model': 'AC18',
        'upnp_manufacturer': 'Tenda'
    }
    
    REJECTION REASONS (documented for transparency):
    - No product name match in banner/headers/body
    - CVE mentions specific vendor but no evidence of that vendor present
    - Low fingerprint confidence (<80%) with no other evidence
    - Port-only or generic service match without version/banner confirmation
    """
    title_desc = (cve.get("title", "") + " " + cve.get("description", "")).lower()
    svc = service_info.get("service_name", "").lower()
    banner = service_info.get("banner", "").lower()
    version = service_info.get("version", "").lower()
    product = service_info.get("product", "").lower()
    
    # 1) CVE ENDPOINT MATCHING: If CVE mentions specific vulnerable endpoint, require it to be reachable
    endpoint_paths = re.findall(r"(/[\w\-\./]+)", title_desc)
    for path in endpoint_paths:
        # Only consider reasonable endpoint paths (not random text)
        if 1 < len(path) < 80 and "/" in path:
            reachable = evidence.get("reachable_paths", [])
            if reachable and path in reachable:
                print(f"✅ CVE {cve['id']} matched: vulnerable endpoint {path} reachable")
                return True
    
    # 2) VENDOR-SPECIFIC CVE: If CVE explicitly mentions a router vendor, require evidence
    router_vendors = {
        "tenda": ["tenda", "ac18", "ac15"],
        "fritz": ["fritz", "avm", "fritz!box"],
        "tp-link": ["tp-link", "tplink"],
        "d-link": ["d-link", "dlink"],
        "netgear": ["netgear"],
        "asus": ["asus router"],
        "cisco": ["cisco"],
        "zyxel": ["zyxel"]
    }
    
    cve_vendor = None
    for vendor, keywords in router_vendors.items():
        if any(kw in title_desc for kw in keywords):
            cve_vendor = vendor
            break
    
    if cve_vendor:
        # This CVE is vendor-specific, require evidence of that vendor
        vendor_keywords = router_vendors[cve_vendor]
        
        # Check banner
        if any(kw in banner for kw in vendor_keywords):
            print(f"✅ CVE {cve['id']} matched: {cve_vendor} found in banner")
            return True
        
        # Check server header
        server_header = evidence.get("server_header", "").lower()
        if any(kw in server_header for kw in vendor_keywords):
            print(f"✅ CVE {cve['id']} matched: {cve_vendor} found in server header")
            return True
        
        # Check HTML title
        html_title = evidence.get("html_title", "").lower()
        if any(kw in html_title for kw in vendor_keywords):
            print(f"✅ CVE {cve['id']} matched: {cve_vendor} found in HTML title")
            return True
        
        # Check body tokens
        body_tokens = evidence.get("body_tokens", [])
        if any(kw in body_tokens for kw in vendor_keywords):
            print(f"✅ CVE {cve['id']} matched: {cve_vendor} found in page body")
            return True
        
        # Check UPnP device info
        upnp_model = evidence.get("upnp_model", "").lower()
        upnp_mfr = evidence.get("upnp_manufacturer", "").lower()
        if any(kw in upnp_model for kw in vendor_keywords) or any(kw in upnp_mfr for kw in vendor_keywords):
            print(f"✅ CVE {cve['id']} matched: {cve_vendor} found in UPnP device info")
            return True
        
        # NO EVIDENCE OF VENDOR -> REJECT
        print(f"🚫 CVE {cve['id']} rejected: mentions {cve_vendor} but no evidence found")
        return False
    
    # 3) VERSION MATCHING: If CVE mentions specific version, require version match
    cve_versions = re.findall(r"\b(\d+\.\d+(?:\.\d+)*)\b", title_desc)
    if cve_versions and version:
        for cve_ver in cve_versions:
            if cve_ver in version:
                print(f"✅ CVE {cve['id']} matched: version {cve_ver} found")
                return True
    
    # 4) PRODUCT MATCHING: If CVE mentions specific product, require product in banner/evidence
    common_products = ["apache", "nginx", "openssh", "bind", "postfix", "mysql", "postgresql", 
                       "miniupnpd", "libupnp", "samba", "vsftpd"]
    
    cve_product = None
    for prod in common_products:
        if prod in title_desc:
            cve_product = prod
            break
    
    if cve_product:
        # Require product name in banner or server header
        if cve_product in banner or cve_product in product:
            print(f"✅ CVE {cve['id']} matched: product {cve_product} found in banner")
            return True
        
        server_header = evidence.get("server_header", "").lower()
        if cve_product in server_header:
            print(f"✅ CVE {cve['id']} matched: product {cve_product} found in server header")
            return True
        
        # No product match
        print(f"🚫 CVE {cve['id']} rejected: mentions {cve_product} but not found in service")
        return False
    
    # 5) HIGH-CONFIDENCE GENERIC MATCH: If fingerprint confidence is high (>=80%) and CVE is generic
    fingerprint_conf = service_info.get("fingerprint_confidence", 0)
    if fingerprint_conf >= 80 and svc in title_desc:
        # Generic service CVE with high confidence fingerprint
        print(f"✅ CVE {cve['id']} matched: high-confidence ({fingerprint_conf}%) generic match")
        return True
    
    # 6) DEFAULT REJECT: No sufficient evidence
    print(f"🚫 CVE {cve['id']} rejected: no evidence (port-only or generic keyword match)")
    return False

def save_cves_to_supabase(cves: List[Dict[str, Any]]):
    """
    Save CVEs into Supabase `cve` table, avoiding duplicates.
    """
    if not supabase:
        print("⚠️ Supabase client not available - skipping CVE storage")
        return
    
    for cve in cves:
        try:
            supabase.table("cve").upsert({
                "cve_id": cve["id"],
                "title": cve.get("title", cve["id"]),
                "description": cve.get("description", "No description"),
                "cvss_score": cve.get("cvss", None)
            }, on_conflict=["cve_id"]).execute()
            print(f"💾 Saved {cve['id']} into Supabase")
        except Exception as e:
            print(f"⚠️ Failed to save {cve['id']} - {e}")

def fetch_cves_for_service(service_name: str, version: str, os_name: str = "unknown", 
                           service_info: Dict[str, Any] = None, evidence: Dict[str, Any] = None) -> List[Dict[str, Any]]:
    """
    Fetch CVEs for a given service and version from NVD API,
    apply smart filters, then save them to Supabase.
    """
    try:
        print(f"🔎 Fetching CVEs for service: {service_name}, version: {version}")
        
        # Detect vendor/product from service info
        product = detect_vendor(service_name, version)
        print(f"🏷️ Detected vendor/product: {product}")
        
        # Skip CVE lookup for truly unknown services
        generic_services = ["upnp", "http-alt", "http-proxy", "https-alt", "ppp", "cslistener", "unknown"]
        if product == "Generic" and (not version or version == "unknown" or version == ""):
            # If it's a completely unknown service, don't fetch CVEs
            if service_name.lower() in generic_services or service_name.lower() == "unknown":
                print(f"⏭️ Skipping CVE lookup for unknown service '{service_name}' without version")
                return []
            # Even if we have a service name, without version info, results will be too broad
            print(f"⚠️ Generic service '{service_name}' without version - skipping to avoid irrelevant results")
            return []
        
        # Construct search query with vendor/product awareness
        search_query = ""
        if product != "Generic":
            # Use detected product name for precise matching
            search_query = product
        elif version and version != "unknown":
            # Extract product name from version string for better CVE matching
            if "nginx" in version.lower():
                search_query = f"nginx {version}"
            elif "apache" in version.lower():
                search_query = f"apache {version}"
            else:
                search_query = f"{service_name} {version}"
        else:
            search_query = service_name
            
        # NVD API endpoint
        url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
        params = {
            "keywordSearch": search_query,
            "resultsPerPage": 5  # limit results for now
        }
        
        print(f"🌐 Querying NVD API with: {search_query}")
        response = requests.get(url, params=params, timeout=10)
        response.raise_for_status()
        
        data = response.json()
        vulnerabilities = data.get("vulnerabilities", [])
        
        cves = []
        for vuln in vulnerabilities:
            cve_data = vuln.get("cve", {})
            cve_id = cve_data.get("id", "Unknown")
            
            # Title or short description
            title = cve_data.get("id", "Unknown CVE")
            
            # Get description
            descriptions = cve_data.get("descriptions", [])
            description = "No description available"
            for desc in descriptions:
                if desc.get("lang") == "en":
                    description = desc.get("value", "No description available")
                    break
            
            # Get severity (CVSS)
            metrics = cve_data.get("metrics", {})
            cvss = None
            if "cvssMetricV31" in metrics:
                cvss = metrics["cvssMetricV31"][0].get("cvssData", {}).get("baseScore")
            elif "cvssMetricV30" in metrics:
                cvss = metrics["cvssMetricV30"][0].get("cvssData", {}).get("baseScore")
            elif "cvssMetricV2" in metrics:
                cvss = metrics["cvssMetricV2"][0].get("cvssData", {}).get("baseScore")
            
            # Build CVE record
            cves.append({
                "id": cve_id,
                "title": title,
                "description": description,
                "cvss": cvss
            })
        
        print(f"✅ Found {len(cves)} raw CVEs for {service_name}")

        # 🔍 STRICT EVIDENCE-BASED FILTERING (NEW)
        if service_info and evidence:
            print(f"🔬 Applying strict evidence-based filtering...")
            cves_before = len(cves)
            cves = [cve for cve in cves if strict_match_cve_to_evidence(cve, service_info, evidence)]
            print(f"🔬 Strict filter: {cves_before} → {len(cves)} CVEs (rejected {cves_before - len(cves)} without evidence)")
        else:
            # Fallback to old filtering if no evidence provided (backward compatibility)
            print(f"⚠️ No evidence provided, using legacy filtering...")
            cves = exclude_unrelated_router_cves(cves, product)  # Remove other vendors first
            cves = filter_cves_by_vendor(cves, product)  # Keep only matching vendor
            cves = exclude_unrelated_cves(cves)  # Generic keyword filtering
            cves = filter_by_age_and_score(cves)  # Filter by year and CVSS
            cves = filter_cves_by_os(os_name, cves)  # OS-specific filtering

        print(f"✅ Final: {len(cves)} relevant CVEs for {service_name}")

        # 🚀 Save to Supabase
        if cves:
            save_cves_to_supabase(cves)
        
        return cves
        
    except requests.exceptions.Timeout:
        print(f"⏰ Timeout fetching CVEs for {service_name}")
        return [{"error": "Timeout while fetching CVE data"}]
    except requests.exceptions.RequestException as e:
        print(f"❌ Network error fetching CVEs for {service_name}: {e}")
        return [{"error": f"Network error: {e}"}]
    except Exception as e:
        print(f"❌ Unexpected error fetching CVEs for {service_name}: {e}")
        traceback.print_exc()
        return [{"error": f"Unexpected error: {e}"}]
