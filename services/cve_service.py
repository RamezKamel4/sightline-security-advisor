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
    "buffalo", "asus router", "belkin", "huawei router"
]

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
        
        # Keep CVEs from 2015 onwards with CVSS >= 5.0
        if year >= 2015 and cvss_score >= 5.0:
            filtered.append(cve)
        elif year == 0 or cvss_score == 0:
            # If we can't determine year or score, keep it (might be legitimate)
            filtered.append(cve)
    
    print(f"🔍 Age/Score filter: {len(cve_results)} → {len(filtered)} CVEs")
    return filtered

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

def fetch_cves_for_service(service_name: str, version: str, os_name: str = "unknown") -> List[Dict[str, Any]]:
    """
    Fetch CVEs for a given service and version from NVD API,
    apply smart filters, then save them to Supabase.
    """
    try:
        print(f"🔎 Fetching CVEs for service: {service_name}, version: {version}")
        
        # Construct search query
        if version and version != "unknown":
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

        # 🔍 Apply filters to improve relevance
        cves = exclude_unrelated_cves(cves)
        cves = filter_by_age_and_score(cves)
        cves = filter_cves_by_os(os_name, cves)

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
