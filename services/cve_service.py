import requests
import traceback
import os
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

def fetch_cves_for_service(service_name: str, version: str) -> List[Dict[str, Any]]:
    """
    Fetch CVEs for a given service and version from NVD API,
    then save them to Supabase.
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
        
        print(f"✅ Found {len(cves)} CVEs for {service_name}")

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
