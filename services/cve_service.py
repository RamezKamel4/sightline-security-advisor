import requests
import traceback
import os
from typing import List, Dict, Any
from datetime import datetime
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
                "cvss_score": cve.get("cvss", None),
                "confidence": cve.get("confidence", "low"),
                "published_year": cve.get("published_year", None)
            }, on_conflict=["cve_id"]).execute()
            print(f"💾 Saved {cve['id']} into Supabase (confidence: {cve.get('confidence', 'low')})")
        except Exception as e:
            print(f"⚠️ Failed to save {cve['id']} - {e}")

def fetch_cves_for_service(service_name: str, version: str) -> List[Dict[str, Any]]:
    """
    Fetch and filter CVEs for a given service and version from NVD API,
    with confidence scoring and version validation.
    """
    try:
        # Skip lookup if version is unknown or empty
        if not version or version.lower() == "unknown":
            print(f"⚠️ Skipping CVE lookup for {service_name} - no version information")
            return []

        print(f"🔎 Fetching CVEs for service: {service_name}, version: {version}")
            
        # NVD API endpoint
        url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
        
        # Use exact version matching in query
        params = {
            "keywordSearch": f"{service_name} {version}",
            "resultsPerPage": 10  # increased to get more potential matches
        }
        
        print(f"🌐 Querying NVD API with: {service_name} {version}")
        response = requests.get(url, params=params, timeout=10)
        response.raise_for_status()
        
        data = response.json()
        vulnerabilities = data.get("vulnerabilities", [])
        
        cves = []
        for vuln in vulnerabilities:
            cve_data = vuln.get("cve", {})
            cve_id = cve_data.get("id", "Unknown")
            
            # Extract publication date for age filtering
            published_date = cve_data.get("published", "")
            if published_date:
                year = int(published_date[:4])
            else:
                year = datetime.now().year  # Use current year if not available
            
            # Get descriptions and normalized product info
            descriptions = cve_data.get("descriptions", [])
            description = "No description available"
            for desc in descriptions:
                if desc.get("lang") == "en":
                    description = desc.get("value", "No description available")
                    break
                    
            # Calculate confidence score based on matches
            confidence = "low"
            
            # Check configurations for exact product and version matches
            configurations = cve_data.get("configurations", [])
            has_product_match = False
            has_version_match = False
            
            for config in configurations:
                for node in config.get("nodes", []):
                    for cpe_match in node.get("cpeMatch", []):
                        cpe_criteria = cpe_match.get("criteria", "").lower()
                        if service_name.lower() in cpe_criteria:
                            has_product_match = True
                            if version.lower() in cpe_criteria:
                                has_version_match = True
                                confidence = "high"
                                break
                    if has_version_match:
                        break
                if has_version_match:
                    break
            
            if has_product_match and not has_version_match:
                confidence = "medium"
                
            # Skip old CVEs if confidence is not high
            if confidence != "high" and year < 2010:
                continue
            
            # Get CVSS score
            metrics = cve_data.get("metrics", {})
            cvss = None
            if "cvssMetricV31" in metrics:
                cvss = metrics["cvssMetricV31"][0].get("cvssData", {}).get("baseScore")
            elif "cvssMetricV30" in metrics:
                cvss = metrics["cvssMetricV30"][0].get("cvssData", {}).get("baseScore")
            elif "cvssMetricV2" in metrics:
                cvss = metrics["cvssMetricV2"][0].get("cvssData", {}).get("baseScore")
            
            # Build enriched CVE record
            cves.append({
                "id": cve_id,
                "title": cve_data.get("id", "Unknown CVE"),
                "description": description,
                "cvss": cvss,
                "confidence": confidence,
                "published_year": year
            })
        
        # Sort by confidence and CVSS score
        cves.sort(key=lambda x: (
            {"high": 3, "medium": 2, "low": 1}[x["confidence"]], 
            x.get("cvss", 0) or 0
        ), reverse=True)
        
        print(f"✅ Found {len(cves)} relevant CVEs for {service_name} {version}")

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
