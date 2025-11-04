
"""
Network Scanning Service with HTTP Verification and Gated CVE Lookup

Gating Logic:
1. Use Nmap -sV output first (may have version)
2. If version missing/ambiguous, probe HTTP headers and TLS
3. Only fetch CVEs when product + version are detected (high confidence)
4. For product-only detection, mark as unconfirmed and provide recommendations
5. Skip CVE lookup for unknown services to avoid false positives
"""

import nmap
import traceback
from fastapi import HTTPException
from services.cve_service import fetch_cves_for_service
from services.service_probe import probe_http_service, probe_banner, merge_detection_results
from services.http_inspector import inspect_http_service, parse_server_header
from typing import List, Dict, Any, Optional
import re
import socket
import subprocess
import ipaddress

# Optional mapping of profiles to NSE scripts for deeper detection
PROFILE_EXTRA_SCRIPTS = {
    "web-apps": "http-enum,http-headers,http-title,ssl-cert,banner",
    "databases": "broadcast-sql-brute,banner,ssl-cert",
    "remote-access": "ssh-hostkey,sshv1,rdp-enum-encryption,banner,ssl-cert",
    "comprehensive": "http-enum,http-headers,http-title,ssl-cert,banner,ssh-hostkey,default,safe"
}

def is_private_cidr(target: str) -> bool:
    """Detect RFC1918 private IP addresses"""
    private_patterns = [
        r'^10\.',
        r'^192\.168\.',
        r'^172\.(1[6-9]|2[0-9]|3[0-1])\.'
    ]
    return any(re.match(pattern, target) for pattern in private_patterns)

def backend_has_raw_socket() -> bool:
    """Check if nmap has raw socket capabilities"""
    try:
        result = subprocess.run(['getcap', '/usr/bin/nmap'], 
                              capture_output=True, text=True, timeout=5)
        return 'cap_net_raw' in result.stdout or 'cap_net_admin' in result.stdout
    except:
        # Fallback: try to detect if running as root
        import os
        return os.geteuid() == 0 if hasattr(os, 'geteuid') else False

def backend_on_subnet(target: str) -> bool:
    """Check if backend has an interface on the same subnet as target"""
    try:
        # Extract first 3 octets for /24 subnet check
        target_subnet = '.'.join(target.split('.')[:3])
        hostname = socket.gethostname()
        local_ips = socket.gethostbyname_ex(hostname)[2]
        
        for ip in local_ips:
            if ip.startswith(target_subnet):
                return True
        return False
    except:
        return False

def build_lan_aware_nmap_args(target: str, base_args: str, scan_profile: str) -> str:
    """Build nmap args - pass through arguments from frontend"""
    # Simply return the args as-is to preserve all flags and options
    print(f"✓ Using nmap arguments for {target}: {base_args}")
    return base_args

def perform_network_scan(ip_address: str, nmap_args: str, scan_profile: str, follow_up: bool = False) -> Dict[str, Any]:
    """
    Perform network scan on the given IP address using nmap.
    
    Args:
        ip_address: Target IP address to scan
        nmap_args: Additional nmap arguments
        scan_profile: Scan profile (web-apps, databases, etc.)
        follow_up: Whether this is a follow-up scan for version detection
        
    Returns:
        Dictionary containing scan results with CVE information, OS detection, and command used
    """
    print(f"🔍 Starting {'follow-up ' if follow_up else ''}scan on {ip_address} with args: {nmap_args}")
    
    try:
        nm = nmap.PortScanner()
        results = []
        host_info = {}
        
        # Apply LAN-aware optimizations
        if not follow_up:
            nmap_args = build_lan_aware_nmap_args(ip_address, nmap_args, scan_profile)
        
        # For follow-up scans, add profile-specific scripts
        if follow_up and scan_profile in PROFILE_EXTRA_SCRIPTS:
            extra_scripts = PROFILE_EXTRA_SCRIPTS[scan_profile]
            if '--script' not in nmap_args:
                nmap_args += f" --script {extra_scripts}"
            print(f"📝 Follow-up scan using scripts: {extra_scripts}")
        
        # Pass target directly to nmap - it handles CIDR, ranges, and single hosts natively
        hosts_arg = ip_address.strip()

        # Build full command for logging
        full_command = f"nmap {nmap_args} {hosts_arg}"
        print(f"🚀 Executing: {full_command}")

        # Execute the scan across all expanded hosts
        nm.scan(hosts=hosts_arg, arguments=nmap_args)
        
        hosts_list = nm.all_hosts()
        if not hosts_list:
            return {
                "results": [],
                "nmap_cmd": full_command,
                "nmap_output": "No hosts found",
                "error": f"Host {ip_address} not found or not scannable."
            }
        
        print(f"🌐 Found {len(hosts_list)} host(s) in scan")
        
        # Process ALL hosts from the scan (important for subnet scans)
        for host in hosts_list:
            host_data = nm[host]
            
            # Extract host metadata (OS detection, MAC, latency, etc.) for first host only
            if not follow_up and host == hosts_list[0]:
                print(f"🖥️  Extracting host information for {host}...")
                
                # OS Detection
                os_matches = host_data.get('osmatch', [])
                if os_matches:
                    host_info['os_matches'] = [
                        {
                            'name': match.get('name', 'Unknown'),
                            'accuracy': match.get('accuracy', 0),
                            'os_class': match.get('osclass', [])
                        }
                        for match in os_matches[:3]  # Top 3 matches
                    ]
                    print(f"🎯 OS Detection: {os_matches[0].get('name')} ({os_matches[0].get('accuracy')}% accuracy)")
                
                # MAC Address
                addresses = host_data.get('addresses', {})
                if 'mac' in addresses:
                    host_info['mac_address'] = addresses['mac']
                    vendor = host_data.get('vendor', {}).get(addresses['mac'], 'Unknown')
                    host_info['mac_vendor'] = vendor
                    print(f"📡 MAC Address: {addresses['mac']} ({vendor})")
                
                # Host state and latency
                if 'status' in host_data:
                    host_info['state'] = host_data['status'].get('state', 'unknown')
                    host_info['reason'] = host_data['status'].get('reason', 'unknown')
                
                # Uptime (if available)
                if 'uptime' in host_data:
                    host_info['uptime'] = {
                        'seconds': host_data['uptime'].get('seconds', 0),
                        'lastboot': host_data['uptime'].get('lastboot', '')
                    }
                
                # Distance (network hops)
                if 'distance' in host_data:
                    host_info['distance'] = host_data['distance']
                    print(f"🌐 Network distance: {host_data['distance']} hops")
                
                # Hostname
                hostnames = host_data.get('hostnames', [])
                if hostnames:
                    host_info['hostnames'] = [h.get('name', '') for h in hostnames if h.get('name')]
                    print(f"🏷️  Hostname: {', '.join(host_info['hostnames'])}")

            # Process ALL TCP ports (open, filtered, closed)
            if 'tcp' not in host_data or not host_data['tcp']:
                print(f"ℹ️  No TCP port data found for {host}")
                continue
            
            tcp_ports = host_data['tcp']
            print(f"🔓 Host {host}: Found {len(tcp_ports)} TCP ports with states: {list(tcp_ports.keys())}")

            for port, port_info in tcp_ports.items():
                port_state = port_info.get('state', 'unknown')
                service_name = port_info.get('name', 'unknown')
                product = port_info.get('product', '').strip()
                version_str = port_info.get('version', '').strip()
                display_version = f"{product} {version_str}".strip() or "unknown"

                # Decide what to search in CVE DB
                search_service_name = product or service_name
                search_version = version_str or "unknown"

                print(f"🔍 Port {port} ({port_state}): {service_name} - {display_version}")

                # Enhanced service detection for HTTP/HTTPS services with gated CVE lookup
                probe_data = {}
                evidence = {}
                final_product = None
                final_version = None
                status = "info"
                recommendations = []
                
                if port_state == "open" and port in [80, 443, 8000, 8080, 8443, 3000, 5000, 9000]:
                    print(f"🔬 Performing HTTP verification on {host}:{port}...")
                    
                    # Determine hostname for proper Host header
                    hostname = host
                    if 'hostnames' in host_info and host_info['hostnames']:
                        hostname = host_info['hostnames'][0]
                    
                    # Inspect HTTP service
                    evidence = inspect_http_service(hostname, host, port)
                    
                    # Also run legacy probe for additional data
                    probe_data = probe_http_service(host, port)
                    
                    # Decision logic for product/version
                    if evidence.get('product') and evidence.get('version'):
                        # HIGH CONFIDENCE: Product + Version from HTTP headers
                        final_product = evidence['product']
                        final_version = evidence['version']
                        search_service_name = final_product
                        search_version = final_version
                        display_version = f"{final_product} {final_version}"
                        status = "vulnerable"  # Will be updated after CVE check
                        print(f"✅ HIGH CONFIDENCE: {final_product} {final_version} (from HTTP headers)")
                        
                    elif evidence.get('product') and not evidence.get('version'):
                        # MEDIUM CONFIDENCE: Product only, no version
                        final_product = evidence['product']
                        final_version = None
                        # Check if nmap had version info
                        if version_str and version_str.lower() != "unknown":
                            final_version = version_str
                            search_service_name = final_product
                            search_version = final_version
                            display_version = f"{final_product} {final_version} (nmap)"
                            status = "vulnerable"
                            print(f"✅ MEDIUM→HIGH: {final_product} {final_version} (product from headers, version from nmap)")
                        else:
                            search_service_name = final_product
                            search_version = None  # Will gate CVE lookup
                            display_version = f"{final_product} (version unknown)"
                            status = "unconfirmed"
                            recommendations.append(
                                "Server header lacks version. CVE lookup skipped to avoid false positives. "
                                "Consider authenticated scan or manual verification."
                            )
                            print(f"⚠️ MEDIUM CONFIDENCE: {final_product} but no version - CVE lookup will be skipped")
                    
                    elif product and version_str:
                        # Fallback to nmap detection
                        final_product = product
                        final_version = version_str
                        search_service_name = final_product
                        search_version = final_version
                        display_version = f"{product} {version_str}"
                        status = "vulnerable"
                        print(f"✅ Using nmap detection: {product} {version_str}")
                    
                    else:
                        # NO PRODUCT/VERSION DETECTED
                        search_service_name = service_name
                        search_version = None  # Will gate CVE lookup
                        display_version = "unknown"
                        status = "info"
                        recommendations.append(
                            "Service detected but product/version could not be determined. "
                            "CVE lookup skipped to prevent false positives."
                        )
                        print(f"⚠️ LOW CONFIDENCE: No product/version detected - CVE lookup will be skipped")
                    
                    # Add evidence-based recommendations
                    if evidence.get('recommendations'):
                        recommendations.extend(evidence['recommendations'])
                    
                    # Merge probe data for additional context
                    if probe_data:
                        merged = merge_detection_results(service_name, display_version, probe_data)
                        if merged.get('conflicts'):
                            print(f"⚠️ Conflicts detected: {merged['conflicts']}")
                    
                    print(f"📋 Final detection: product={final_product}, version={final_version}, status={status}")
                
                # Build detection methods list
                detection_methods = probe_data.get('detection_methods', ['nmap']) if probe_data else ['nmap']
                if evidence:
                    if evidence.get('evidence_sources'):
                        detection_methods.extend(evidence['evidence_sources'])
                
                # Build evidence dict for storage
                evidence_data = {
                    "sources": list(set(detection_methods)),
                    "http_headers": evidence.get('http_headers', {}),
                    "tls_info": evidence.get('tls_info', {}),
                    "redirect_to_https": evidence.get('redirect_to_https', False),
                    "confidence_level": evidence.get('confidence', 'low'),
                    "recommendations": recommendations
                }
                
                service_data = {
                    "host": host,
                    "port": port,
                    "state": port_state,
                    "service": service_name,
                    "version": display_version,
                    "cves": [],
                    "confidence": probe_data.get('confidence', 50.0) if probe_data else 50.0,
                    "raw_banner": probe_data.get('raw_banner', ''),
                    "headers": evidence.get('http_headers', probe_data.get('headers', {})),
                    "tls_info": evidence.get('tls_info', probe_data.get('tls_info', {})),
                    "proxy_detection": probe_data.get('proxy_detection', {}),
                    "detection_methods": evidence_data,
                    "status": status,
                    "recommendations": recommendations
                }

                # GATED CVE ENRICHMENT
                # Only fetch CVEs when we have high confidence (product + version)
                if port_state == "open" and search_service_name.lower() != "unknown":
                    # Check if we have version info (gating condition)
                    has_version = search_version and search_version.lower() != "unknown"
                    
                    if has_version:
                        # HIGH CONFIDENCE: Fetch CVEs
                        try:
                            print(f"🔓 GATED CVE LOOKUP: Fetching CVEs for {search_service_name} {search_version}")
                            cve_result = fetch_cves_for_service(search_service_name, search_version, require_version=True)
                            
                            # Extract prioritized CVE data
                            top_cves = cve_result.get("top_cves", [])
                            omitted_count = cve_result.get("omitted_count", 0)
                            summary_note = cve_result.get("summary_note")
                            total_cves = cve_result.get("total_cves", 0)
                            
                            # Store CVE data with metadata
                            service_data["cves"] = top_cves
                            service_data["cve_metadata"] = {
                                "total_cves": total_cves,
                                "omitted_count": omitted_count,
                                "summary_note": summary_note
                            }
                            
                            if top_cves:
                                # Check if any high-severity CVEs in top results
                                high_severity = any(cve.get('cvss', 0) and cve['cvss'] >= 7.0 for cve in top_cves)
                                service_data["status"] = "vulnerable" if high_severity else "low_risk"
                                print(f"📄 Found {total_cves} total CVEs (showing top {len(top_cves)}) for {search_service_name} {search_version}")
                                if omitted_count > 0:
                                    print(f"   ⚠️ {omitted_count} additional CVEs omitted for brevity")
                            else:
                                service_data["status"] = "no_cves_found"
                                print(f"✅ No CVEs found for {search_service_name} {search_version}")
                        except Exception as e:
                            print(f"⚠️ Error fetching CVEs for {search_service_name}: {e}")
                            traceback.print_exc()
                            service_data["cves"] = [{"error": f"Could not fetch CVEs: {e}"}]
                            service_data["cve_metadata"] = {
                                "total_cves": 0,
                                "omitted_count": 0,
                                "summary_note": None
                            }
                    else:
                        # NO VERSION: Skip CVE lookup to avoid false positives
                        print(f"🚫 GATED CVE LOOKUP: Skipping {search_service_name} - no version (avoiding false positives)")
                        service_data["cves"] = []
                        service_data["status"] = "unconfirmed"
                        if "Server detected but version unknown" not in recommendations:
                            service_data["recommendations"].append(
                                f"Product '{search_service_name}' detected but version unknown. "
                                "CVE lookup skipped to prevent false positives. "
                                "Run authenticated scan or check server configuration for precise version."
                            )

                results.append(service_data)

        print(f"✅ Scan completed successfully")
        print(f"📊 Found {len(results)} port entries across {len(hosts_list)} host(s)")
        
        # Return results, metadata, and host information
        return {
            "results": results,
            "nmap_cmd": full_command,
            "nmap_output": nm.csv() if hasattr(nm, 'csv') else str(nm.all_hosts()),
            "host_info": host_info if host_info else None
        }

    except nmap.PortScannerError as e:
        print(f"❌ Nmap scanner error: {e}")
        return {
            "results": [],
            "nmap_cmd": f"nmap {nmap_args} {ip_address}",
            "nmap_output": f"Error: {str(e)}",
            "error": str(e),
            "host_info": None
        }
    except Exception as e:
        print(f"❌ Unexpected error during scan: {e}")
        traceback.print_exc()
        return {
            "results": [],
            "nmap_cmd": f"nmap {nmap_args} {ip_address}",
            "nmap_output": f"Error: {str(e)}",
            "error": str(e),
            "host_info": None
        }
