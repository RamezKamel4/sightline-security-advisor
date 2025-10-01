
import nmap
import traceback
from fastapi import HTTPException
from services.cve_service import fetch_cves_for_service
from typing import List, Dict, Any

# Optional mapping of profiles to NSE scripts for deeper detection
PROFILE_EXTRA_SCRIPTS = {
    "web-apps": "http-enum,http-headers,http-title,ssl-cert,banner",
    "databases": "broadcast-sql-brute,banner,ssl-cert",
    "remote-access": "ssh-hostkey,sshv1,rdp-enum-encryption,banner,ssl-cert",
    "comprehensive": "default,safe"
}

def perform_network_scan(ip_address: str, nmap_args: str, scan_profile: str, follow_up: bool = False) -> List[Dict[str, Any]]:
    """
    Perform network scan on a target IP address.
    If follow_up=True, we assume only specific ports are being scanned for unknown services.
    """
    print(f"🚀 Starting scan on {ip_address} | Profile: {scan_profile} | Args: {nmap_args} | Follow-up: {follow_up}")
    
    try:
        nm = nmap.PortScanner()
        results = []

        # Optionally append profile-specific NSE scripts for follow-ups
        if follow_up and scan_profile in PROFILE_EXTRA_SCRIPTS:
            nmap_args = f"{nmap_args} --script {PROFILE_EXTRA_SCRIPTS[scan_profile]}"
            print(f"🛠️ Follow-up scan using extra scripts for profile '{scan_profile}': {nmap_args}")

        print(f"🔍 Executing nmap scan: nmap {nmap_args} {ip_address}")
        nm.scan(ip_address, arguments=nmap_args)
        
        hosts_list = nm.all_hosts()
        if not hosts_list:
            raise HTTPException(status_code=404, detail=f"Host {ip_address} not found or not scannable.")
        
        host = hosts_list[0]
        host_data = nm[host]

        if 'tcp' not in host_data or not host_data['tcp']:
            return [{"message": f"No open TCP ports found on {ip_address}."}]
        
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

        return results

    except nmap.PortScannerError as e:
        print(f"❌ Nmap Scanner Error: {e}")
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=f"Nmap scan error: {e}")
    except HTTPException:
        raise
    except Exception as e:
        print(f"❌ Unexpected error during scan: {e}")
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=f"Unexpected error: {e}")
