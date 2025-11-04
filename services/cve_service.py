import requests
import traceback
import os
import time
from typing import List, Dict, Any, Optional
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

# In-memory cache for CVE results to respect NVD rate limits
# Cache key: (service_name, version) -> (cves, timestamp)
_cve_cache: Dict[tuple, tuple] = {}
_cache_ttl = 3600  # 1 hour cache

def parse_version(version_str: str) -> List[int]:
    """
    Parse version string into comparable list of integers.
    Examples: "2.10.5" -> [2, 10, 5], "1.0" -> [1, 0]
    """
    try:
        return [int(part) for part in version_str.replace('-', '.').split('.') if part.isdigit()]
    except (ValueError, AttributeError):
        return []

def compare_versions(v1: str, v2: str) -> int:
    """
    Compare two version strings semantically.
    Returns: -1 if v1 < v2, 0 if equal, 1 if v1 > v2
    """
    parts1 = parse_version(v1)
    parts2 = parse_version(v2)
    
    # Pad shorter version with zeros
    max_len = max(len(parts1), len(parts2))
    parts1.extend([0] * (max_len - len(parts1)))
    parts2.extend([0] * (max_len - len(parts2)))
    
    if parts1 < parts2:
        return -1
    elif parts1 > parts2:
        return 1
    return 0

def is_version_in_range(version: str, start: Optional[str], end: Optional[str]) -> bool:
    """
    Check if version falls within the specified range using semantic version comparison.
    """
    if not version or version.lower() == "unknown":
        return False
    
    version = version.lower().strip()
    
    if start:
        if compare_versions(version, start.lower().strip()) < 0:
            return False
    
    if end:
        if compare_versions(version, end.lower().strip()) > 0:
            return False
    
    return True

def fetch_cves_for_service(
    service_name: str, 
    version: Optional[str] = None,
    require_version: bool = True
) -> List[Dict[str, Any]]:
    """
    Fetch and filter CVEs for a given service and version from NVD API,
    with confidence scoring and version validation.
    
    Args:
        service_name: Product name (e.g., "apache_httpd", "nginx")
        version: Version string (can be None)
        require_version: If True, skip lookup when version is missing (default: True)
    
    Returns:
        List of CVE dictionaries with confidence scoring
    """
    # Initialize variables at function start to avoid NameError
    matched_products = set()
    cvss_info = {'score': None, 'version': None, 'vector': None, 'severity': None}
    
    try:
        # Gating logic: skip lookup if version is unknown or empty and required
        if require_version and (not version or version.lower() == "unknown"):
            print(f"🚫 Gated CVE lookup: {service_name} has no version - skipping to avoid false positives")
            return []
        
        # Check cache first
        cache_key = (service_name, version or "")
        if cache_key in _cve_cache:
            cached_cves, cached_time = _cve_cache[cache_key]
            if time.time() - cached_time < _cache_ttl:
                print(f"💾 Using cached CVE results for {service_name} {version}")
                return cached_cves

        print(f"🔎 Fetching CVEs for service: {service_name}, version: {version}")
            
        # NVD API endpoint
        url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
        
        # Generate multiple search variations for better coverage
        search_terms = [(service_name, version or "")]
        
        # Add known product name variations
        service_lower = service_name.lower()
        if "big-ip" in service_lower or "f5" in service_lower:
            search_terms.extend([("f5", ""), ("big-ip", ""), ("f5 big-ip", "")])
        elif "apache" in service_lower or "httpd" in service_lower:
            search_terms.extend([("apache", ""), ("httpd", ""), ("apache httpd", "")])
        elif "nginx" in service_lower:
            search_terms.append(("nginx", ""))
        
        # Track queries to avoid duplicates
        seen_queries = set()
        all_cves = []
        
        # Try each search term combination
        for idx, (service_term, version_term) in enumerate(search_terms):
            if not service_term:
                continue
            
            # Create cache key to avoid duplicate queries
            query_key = f"{service_term}:{version_term}"
            if query_key in seen_queries:
                continue
            seen_queries.add(query_key)
            
            # Build query parameters
            params = {"resultsPerPage": 15, "keywordSearch": service_term}
            
            print(f"🔍 Searching CVEs - Query: '{service_term}'")
            
            # ⏰ RATE LIMITING: Wait 6 seconds between API calls (NVD allows 5 requests per 30 seconds)
            if idx > 0:
                print("⏰ Rate limiting: waiting 6 seconds...")
                time.sleep(6)
            
            # Make API request
            try:
                response = requests.get(url, params=params, timeout=10)
                response.raise_for_status()
                
                data = response.json()
                current_vulns = data.get("vulnerabilities", [])
                
                # Add new vulnerabilities, avoiding duplicates
                for vuln in current_vulns:
                    cve_id = vuln.get("cve", {}).get("id")
                    if cve_id and not any(c.get("cve", {}).get("id") == cve_id for c in all_cves):
                        all_cves.append(vuln)
                
                print(f"  Found {len(current_vulns)} CVEs for '{service_term}'")
            
            except requests.exceptions.Timeout:
                print(f"⏰ Timeout fetching CVEs for {service_term}")
                continue
            except requests.exceptions.RequestException as e:
                print(f"❌ Network error fetching CVEs for {service_term}: {e}")
                continue
        
        # Process and score all collected CVEs
        cves = []
        for vuln in all_cves:
            cve_data = vuln.get("cve", {})
            cve_id = cve_data.get("id", "Unknown")
            
            # Extract publication date for age filtering
            published_date = cve_data.get("published", "")
            if published_date:
                year = int(published_date[:4])
            else:
                year = 2025  # Default to current year if not available
            
            # Get descriptions
            descriptions = cve_data.get("descriptions", [])
            description = "No description available"
            for desc in descriptions:
                if desc.get("lang") == "en":
                    description = desc.get("value", "No description available")
                    break
                    
            # Calculate confidence score based on matches
            confidence = "low"
            has_product_match = False
            has_version_match = False
            
            # Check configurations for exact product and version matches
            configurations = cve_data.get("configurations", [])
            for config in configurations:
                for node in config.get("nodes", []):
                    for cpe_match in node.get("cpeMatch", []):
                        cpe_criteria = cpe_match.get("criteria", "").lower()
                        service_lower = service_name.lower()
                        
                        # Product matching
                        if service_lower in cpe_criteria:
                            has_product_match = True
                            matched_products.add(service_lower)
                            
                            # Version matching with semantic comparison
                            if version and version.lower() != "unknown":
                                version_start = cpe_match.get("versionStartIncluding") or cpe_match.get("versionStartExcluding")
                                version_end = cpe_match.get("versionEndIncluding") or cpe_match.get("versionEndExcluding")
                                
                                # Check exact version match in CPE
                                if f":{version.lower()}" in cpe_criteria:
                                    has_version_match = True
                                    confidence = "high"
                                    break
                                
                                # Check version range with semantic comparison
                                elif version_start or version_end:
                                    if is_version_in_range(version, version_start, version_end):
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
            
            # Extract CVSS information
            metrics = cve_data.get("metrics", {})
            cvss_info = {'score': None, 'version': None, 'vector': None, 'severity': None}
            
            # Try CVSS versions in order of preference
            for metric_type in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
                if metric_type in metrics and metrics[metric_type]:
                    metric = metrics[metric_type][0]
                    cvss_data = metric.get("cvssData", {})
                    
                    if cvss_data:
                        cvss_info['score'] = cvss_data.get("baseScore")
                        cvss_info['version'] = metric_type.replace("cvssMetric", "")
                        cvss_info['vector'] = cvss_data.get("vectorString")
                        
                        # Determine severity
                        if cvss_info['score'] is not None:
                            if cvss_info['score'] >= 9.0:
                                cvss_info['severity'] = "CRITICAL"
                            elif cvss_info['score'] >= 7.0:
                                cvss_info['severity'] = "HIGH"
                            elif cvss_info['score'] >= 4.0:
                                cvss_info['severity'] = "MEDIUM"
                            else:
                                cvss_info['severity'] = "LOW"
                            break
            
            cvss = cvss_info['score']
            
            # Build enriched CVE record
            cves.append({
                "id": cve_id,
                "title": cve_data.get("id", "Unknown CVE"),
                "description": description,
                "cvss": cvss,
                "confidence": confidence,
                "published_year": year,
                "matched_products": list(matched_products),
                "cvss_details": cvss_info
            })
        
        # Sort by confidence and CVSS score
        cves.sort(key=lambda x: (
            {"high": 3, "medium": 2, "low": 1}[x["confidence"]], 
            x.get("cvss", 0) or 0
        ), reverse=True)
        
        print(f"✅ Found {len(cves)} relevant CVEs for {service_name} {version}")

        # 🚀 Save to Supabase in batches
        if cves:
            batch_size = 50
            for i in range(0, len(cves), batch_size):
                batch = cves[i:i + batch_size]
                save_cves_to_supabase(batch)
        
        # Cache results
        _cve_cache[cache_key] = (cves, time.time())
        
        return cves
        
    except requests.exceptions.Timeout:
        print(f"⏰ Timeout fetching CVEs for {service_name}")
        return []  # Return empty list instead of error object
    except requests.exceptions.RequestException as e:
        print(f"❌ Network error fetching CVEs for {service_name}: {e}")
        return []  # Return empty list instead of error object
    except Exception as e:
        print(f"❌ Unexpected error fetching CVEs for {service_name}: {e}")
        traceback.print_exc()
        return []  # Return empty list instead of error object
