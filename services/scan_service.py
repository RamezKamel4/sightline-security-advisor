
import nmap
import traceback
from fastapi import HTTPException
from services.cve_service import fetch_cves_for_service
from typing import List, Dict, Any
import re
import socket
import subprocess

# Optional mapping of profiles to NSE scripts for deeper detection
PROFILE_EXTRA_SCRIPTS = {
    "web-apps": "http-enum,http-headers,http-title,ssl-cert,banner",
    "databases": "broadcast-sql-brute,banner,ssl-cert",
    "remote-access": "ssh-hostkey,sshv1,rdp-enum-encryption,banner,ssl-cert",
    "comprehensive": "default,safe"
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
    """Build nmap args optimized for LAN scanning when applicable"""
    args_parts = base_args.split()
    
    # Check if we should use LAN-specific optimizations
    is_private = is_private_cidr(target)
    has_raw = backend_has_raw_socket()
    on_subnet = backend_on_subnet(target)
    
    # Always add service detection
    if '-sV' not in base_args:
        args_parts.append('-sV')
    
    # Use SYN scan if we have raw socket capability
    if has_raw and '-sS' not in base_args and '-sT' not in base_args:
        args_parts.append('-sS')
    elif not has_raw and '-sT' not in base_args and '-sS' not in base_args:
        args_parts.append('-sT')
    
    # Use ARP discovery for local LAN targets
    if is_private and on_subnet and has_raw:
        if '-PR' not in base_args:
            args_parts.append('-PR')
        print(f"✓ LAN scan optimized: Using ARP discovery for {target}")
    else:
        # Fallback to -Pn for non-LAN or when ICMP might be blocked
        if '-Pn' not in base_args and '-PR' not in base_args:
            args_parts.append('-Pn')
    
    return ' '.join(args_parts)

def perform_network_scan(ip_address: str, nmap_args: str, scan_profile: str, follow_up: bool = False) -> Dict[str, Any]:
    """
    Perform network scan on the given IP address using nmap.
    
    Args:
        ip_address: Target IP address to scan
        nmap_args: Additional nmap arguments
        scan_profile: Scan profile (web-apps, databases, etc.)
        follow_up: Whether this is a follow-up scan for version detection
        
    Returns:
        Dictionary containing scan results with CVE information and command used
    """
    print(f"🔍 Starting {'follow-up ' if follow_up else ''}scan on {ip_address} with args: {nmap_args}")
    
    try:
        nm = nmap.PortScanner()
        results = []
        
        # Apply LAN-aware optimizations
        if not follow_up:
            nmap_args = build_lan_aware_nmap_args(ip_address, nmap_args, scan_profile)
        
        # For follow-up scans, add profile-specific scripts
        if follow_up and scan_profile in PROFILE_EXTRA_SCRIPTS:
            extra_scripts = PROFILE_EXTRA_SCRIPTS[scan_profile]
            if '--script' not in nmap_args:
                nmap_args += f" --script {extra_scripts}"
            print(f"📝 Follow-up scan using scripts: {extra_scripts}")
        
        # Build full command for logging
        full_command = f"nmap {nmap_args} {ip_address}"
        print(f"🚀 Executing: {full_command}")
        
        # Execute the scan
        nm.scan(hosts=ip_address, arguments=nmap_args)
        
        hosts_list = nm.all_hosts()
        if not hosts_list:
            return {
                "results": [],
                "nmap_cmd": full_command,
                "nmap_output": "No hosts found",
                "error": f"Host {ip_address} not found or not scannable."
            }
        
        host = hosts_list[0]
        host_data = nm[host]

        if 'tcp' not in host_data or not host_data['tcp']:
            return {
                "results": [],
                "nmap_cmd": full_command,
                "nmap_output": nm.csv() if hasattr(nm, 'csv') else str(nm.all_hosts()),
                "message": f"No open TCP ports found on {ip_address}."
            }
        
        tcp_ports = host_data['tcp']
        print(f"🔓 Found {len(tcp_ports)} TCP ports: {list(tcp_ports.keys())}")

        for port, port_info in tcp_ports.items():
            service_name = port_info.get('name', 'unknown')
            product = port_info.get('product', '').strip()
            version_str = port_info.get('version', '').strip()
            display_version = f"{product} {version_str}".strip() or "unknown"

            # Decide what to search in CVE DB
            search_service_name = product or service_name
            search_version = version_str or "unknown"

            print(f"🔍 Port {port}: {service_name} - {display_version}")

            service_data = {
                "host": host,
                "port": port,
                "service": service_name,
                "version": display_version,
                "cves": []
            }

            # CVE enrichment
            if search_service_name.lower() != "unknown":
                try:
                    cves = fetch_cves_for_service(search_service_name, search_version)
                    service_data["cves"] = cves
                    print(f"📄 Found {len(cves)} CVEs for {search_service_name}")
                except Exception as e:
                    print(f"⚠️ Error fetching CVEs for {search_service_name}: {e}")
                    traceback.print_exc()
                    service_data["cves"] = [{"error": f"Could not fetch CVEs: {e}"}]

            results.append(service_data)

        print(f"✅ Scan completed successfully")
        print(f"📊 Found {len(results)} services")
        
        # Return both results and metadata
        return {
            "results": results,
            "nmap_cmd": full_command,
            "nmap_output": nm.csv() if hasattr(nm, 'csv') else str(nm.all_hosts())
        }

    except nmap.PortScannerError as e:
        print(f"❌ Nmap scanner error: {e}")
        return {
            "results": [],
            "nmap_cmd": f"nmap {nmap_args} {ip_address}",
            "nmap_output": f"Error: {str(e)}",
            "error": str(e)
        }
    except Exception as e:
        print(f"❌ Unexpected error during scan: {e}")
        traceback.print_exc()
        return {
            "results": [],
            "nmap_cmd": f"nmap {nmap_args} {ip_address}",
            "nmap_output": f"Error: {str(e)}",
            "error": str(e)
        }
