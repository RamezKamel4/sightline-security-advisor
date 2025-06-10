
import nmap
import traceback
from fastapi import HTTPException
from services.cve_service import fetch_cves_for_service

def perform_network_scan(ip_address: str, nmap_args: str, scan_profile: str) -> list:
    """
    Perform network scan on target IP address
    """
    print(f"🚀 Starting scan on {ip_address} with profile: {scan_profile}, args: {nmap_args}")
    
    try:
        nm = nmap.PortScanner()
        results = []

        # Use the provided nmap arguments for the scan
        print(f"🔍 Executing nmap scan: nmap {nmap_args} {ip_address}")
        nm.scan(ip_address, arguments=nmap_args)
        
        print(f"📊 Scan completed. Found hosts: {nm.all_hosts()}")
        
        if not nm.all_hosts():
            print(f"❌ No hosts found for {ip_address}")
            raise HTTPException(status_code=404, detail=f"Host {ip_address} not found or not scannable.")

        host = nm.all_hosts()[0]
        print(f"🏠 Processing host: {host}")
        
        if host not in nm:
            print(f"❌ Host {host} not in scan results")
            return {"message": f"Host {ip_address} did not respond to scan probes."}
            
        if 'tcp' not in nm[host]:
            print(f"ℹ️ No TCP ports found on {host}")
            return {"message": f"No open TCP ports found on {ip_address}."}

        tcp_ports = nm[host]['tcp']
        print(f"🔓 Found {len(tcp_ports)} open ports: {list(tcp_ports.keys())}")

        for port in tcp_ports:
            port_info = tcp_ports[port]
            service_name = port_info.get('name', 'unknown')
            product = port_info.get('product', '').strip()
            version_str = port_info.get('version', '').strip()

            # Determine what to search for in CVE database
            search_service_name = product if product else service_name
            search_version = version_str if version_str else "unknown"
            display_version = f"{product} {version_str}".strip() if product or version_str else 'unknown'
            if not display_version:
                display_version = 'unknown'

            print(f"🔍 Port {port}: {service_name} - {display_version}")

            service_data = {
                "port": port,
                "service": service_name,
                "version": display_version,
                "cves": []
            }

            # Try CVE fetching with detailed debug logging
            if search_service_name != 'unknown':
                try:
                    print(f"🔎 Fetching CVEs for: {search_service_name} {search_version}")
                    cves = fetch_cves_for_service(search_service_name, search_version)
                    service_data["cves"] = cves
                    print(f"📄 Found {len(cves)} CVEs for {search_service_name}")
                except Exception as e:
                    print(f"⚠️ Error while fetching CVEs for {search_service_name}: {e}")
                    traceback.print_exc()
                    service_data["cves"] = [{"error": f"Could not fetch CVEs: {e}"}]

            results.append(service_data)

        if not results:
            return {"message": f"No services with version information found on {ip_address}."}

        print(f"🎉 Scan completed successfully. Found {len(results)} services.")
        return results

    except nmap.PortScannerError as e:
        print(f"❌ Nmap Scanner Error: {e}")
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=f"Nmap scan error: {e}")
    except HTTPException:
        # Re-raise HTTP exceptions
        raise
    except Exception as e:
        print(f"❌ Unexpected error during scan: {e}")
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=f"An unexpected error occurred during scan: {e}")
