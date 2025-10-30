# Evidence-Based CVE Matching

## Overview

VulnScan AI uses **strict evidence-based CVE correlation** to eliminate false positives. CVEs are only assigned to services when there is concrete evidence that the vulnerability applies to the scanned target.

## Core Principle

**No port-only or generic service name matching** - Port numbers and generic service names alone are NOT sufficient to assign vendor-specific CVEs.

## Required Evidence Signals

CVEs are assigned ONLY when at least ONE of the following evidence signals is present:

### 1. Product/Vendor Name Match
- Exact product name or vendor appears in HTTP headers (`Server`, `X-Powered-By`)
- Product name found in HTML title or page body (first 8KB scanned)
- Service banner explicitly mentions the product/vendor
- UPnP device description XML contains matching vendor/model

**Example:**
- ✅ Server header: `Tenda AC18` → Tenda CVEs allowed
- ❌ Generic UPnP service with no vendor info → Tenda CVEs rejected

### 2. Version String Match
- Exact version string from CVE appears in service banner or headers
- Version detected by Nmap fingerprinting with high confidence (≥80%)

**Example:**
- ✅ `Apache/2.4.58` banner + CVE mentions 2.4.58 → Match
- ❌ Generic HTTP service + CVE mentions specific version → Rejected

### 3. Vulnerable Endpoint Detection
- CVE mentions specific endpoint path (e.g., `/goform/SetUpnpCfg`)
- Endpoint is confirmed reachable on target (returns 200/401/403/302)
- Non-destructive GET requests only

**Example:**
- ✅ CVE mentions `/goform/SetUpnpCfg` AND endpoint exists → Match
- ❌ CVE mentions Tenda endpoint but endpoint not found → Rejected

### 4. High-Confidence Fingerprinting
- Nmap fingerprint confidence ≥80%
- Banner includes recognizable implementation string (e.g., `miniupnpd`, `libupnp`)
- Product name explicitly stated in service response

## Implementation

### Key Files

- `services/banner_utils.py` - Evidence extraction utilities
- `services/cve_service.py` - Strict CVE matching logic (`strict_match_cve_to_evidence()`)
- `services/scan_service.py` - Evidence collection and integration
- `tests/test_cve_matching.py` - Unit tests for matching logic

### Evidence Collection Process

1. **Nmap Scanning** - Service detection, version, and banner info
2. **HTTP Probing** - Fetch headers, page content, UPnP device descriptions
3. **Endpoint Testing** - Check for vulnerable paths (non-destructive)
4. **CVE Fetching** - Query NVD API with service+version
5. **Strict Filtering** - Apply `strict_match_cve_to_evidence()` to each CVE
6. **Result Logging** - Document why CVEs were accepted/rejected

### Example Evidence Collection

```python
# For HTTP service on port 80
evidence = {
    "server_header": "Apache/2.4.58 (Ubuntu)",
    "html_title": "Welcome to Apache",
    "body_tokens": ["apache"],
    "reachable_paths": [],
    "upnp_model": "",
    "upnp_manufacturer": ""
}

service_info = {
    "service_name": "http",
    "banner": "Apache/2.4.58",
    "version": "2.4.58",
    "product": "Apache",
    "fingerprint_confidence": 95
}

# CVE will only match if it mentions "apache" or "2.4.58"
```

## Rejection Scenarios

CVEs are REJECTED in these cases:

1. **Cross-Vendor Contamination**
   - Scanning FRITZ!Box but CVE mentions Tenda → Rejected
   - No Tenda-specific evidence present

2. **Port-Only Matching**
   - Port 5000 open + generic UPnP CVE → Rejected without product evidence
   - Port number alone is never sufficient

3. **Low Confidence with No Evidence**
   - Fingerprint confidence <80% + no banner/header/version match → Rejected

4. **Version Mismatch**
   - CVE for Apache 2.4.58 but service is 2.4.60 → Rejected (if strict version checking enabled)

5. **Generic Service without Specifics**
   - Service: "http", no version, no product name → Only generic HTTP CVEs allowed

## Logging and Transparency

All CVE acceptance/rejection decisions are logged:

```
✅ CVE-2023-12345 matched: tenda found in server header
🚫 CVE-2025-11327 rejected: mentions tenda but no evidence found
🚫 CVE-2024-98765 rejected: no evidence (port-only match)
```

Users can review these logs to understand why specific CVEs were/weren't reported.

## Testing

Run unit tests to verify matching logic:

```bash
cd backend
pytest tests/test_cve_matching.py -v
```

**Test Cases:**
- PC with miniupnpd → Tenda CVEs rejected ✅
- Real Tenda device → Tenda CVEs accepted ✅
- FRITZ!Box with evidence → FRITZ CVEs accepted ✅
- Generic Apache → Only Apache CVEs accepted ✅
- Unknown service → Vendor-specific CVEs rejected ✅

## Benefits

1. **Eliminates False Positives** - No more Tenda CVEs on Windows PCs
2. **Increases Trust** - Users see only relevant vulnerabilities
3. **Better Prioritization** - Security teams focus on real risks
4. **Audit Trail** - Transparent reasoning for CVE assignments
5. **Compliance Ready** - Evidence-based reports for audits

## Configuration

No configuration required - evidence-based matching is enabled by default for all scans.

For legacy behavior (not recommended), set `STRICT_CVE_MATCHING=false` in environment variables.
