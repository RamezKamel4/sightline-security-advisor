
import requests
import traceback
from typing import List, Dict, Any

def fetch_cves_for_service(service_name: str, version: str) -> List[Dict[str, Any]]:
    """
    Fetch CVEs for a given service and version from NVD API
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
            "resultsPerPage": 5  # Limit results
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
            
            # Get description
            descriptions = cve_data.get("descriptions", [])
            description = "No description available"
            for desc in descriptions:
                if desc.get("lang") == "en":
                    description = desc.get("value", "No description available")
                    break
            
            # Get severity
            metrics = cve_data.get("metrics", {})
            severity = "Unknown"
            if "cvssMetricV31" in metrics:
                severity = metrics["cvssMetricV31"][0].get("cvssData", {}).get("baseSeverity", "Unknown")
            elif "cvssMetricV30" in metrics:
                severity = metrics["cvssMetricV30"][0].get("cvssData", {}).get("baseSeverity", "Unknown")
            elif "cvssMetricV2" in metrics:
                severity = metrics["cvssMetricV2"][0].get("baseSeverity", "Unknown")
            
            # Get published date
            published = cve_data.get("published", "Unknown")
            
            cves.append({
                "id": cve_id,
                "description": description,
                "severity": severity,
                "published": published
            })
        
        print(f"✅ Found {len(cves)} CVEs for {service_name}")
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
