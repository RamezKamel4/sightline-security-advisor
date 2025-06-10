
import nmap
import traceback
from fastapi import HTTPException
from services.cve_service import fetch_cves_for_service

def perform_network_scan(ip_address: str, nmap_args: str, scan_profile: str) -> list:
    """
    Perform network scan on target IP address
    """
    print(f"Starting scan on {ip_address} with profile: {scan_profile}, args: {nmap_args}")
    
    nm = nmap.PortScanner()
    results = []

    try:
        # Use the provided nmap arguments for the scan
        print(f"Executing nmap scan: nmap {nmap_args} {ip_address}")
        nm.scan(ip_address, arguments=nmap_args)
    except nmap.PortScannerError as e:
        print("Nmap Scanner Error:", e)
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=f"Nmap scan error: {e}")
    except Exception as e:
        print("Unexpected Nmap error:", e)
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=f"An unexpected error occurred during Nmap scan: {e}")

    if not nm.all_hosts():
        raise HTTPException(status_code=404, detail=f"Host {ip_address} not found or not scannable.")

    host = nm.all_hosts()[0]
    if host not in nm or 'tcp' not in nm[host]:
        return {"message": f"No open TCP ports found on {ip_address} or host did not respond to scan probes."}

    for port in nm[host]['tcp']:
        port_info = nm[host]['tcp'][port]
        service_name = port_info.get('name', 'unknown')
        product = port_info.get('product', '').strip()
        version_str = port_info.get('version', '').strip()

        search_service_name = product if product else service_name
        search_version = version_str if version_str else "unknown"
        display_version = f"{product} {version_str}".strip() if product or version_str else 'unknown'
        if not display_version:
            display_version = 'unknown'

        service_data = {
            "port": port,
            "service": service_name,
            "version": display_version,
            "cves": []
        }

        # Try CVE fetching with detailed debug logging
        if search_service_name != 'unknown':
            try:
                print(f"Fetching CVEs for: {search_service_name} {search_version}")
                cves = fetch_cves_for_service(search_service_name, search_version)
                service_data["cves"] = cves
            except Exception as e:
                print("⚠️ Error while fetching CVEs:", e)
                traceback.print_exc()
                service_data["cves"] = ["Error fetching CVEs"]

        results.append(service_data)

    if not results:
        return {"message": f"No services with version information found on {ip_address}."}

    print(f"Scan completed. Found {len(results)} services.")
    return results
