type DepthKey = 'fast' | 'deep' | 'aggressive';
type ProfileKey = 'web-apps' | 'databases' | 'remote-access' | 'comprehensive';

const scanDepthMapping: Record<DepthKey, string> = {
  'fast': '-T4',
  'deep': '-T4 -sV -O',
  'aggressive': '-T4 -A -sC -sV'
};

const scanProfilePorts: Record<ProfileKey, string> = {
  'web-apps': '-p 80,443,8080,8443,3000,5000,8000,9000',
  'databases': '-p 3306,5432,1433,1521,27017,6379,11211,9042',
  'remote-access': '-p 22,3389,5900,1194,1723,4899,5800,5801',
  'comprehensive': '-p 80,443,8080,8443,3000,5000,8000,9000,3306,5432,1433,1521,27017,6379,11211,9042,22,3389,5900,1194,1723,4899,5800,5801'
};

const profileExtraScripts: Record<ProfileKey, string> = {
  'web-apps': 'http-enum,http-headers,http-title,ssl-cert,banner',
  'databases': 'broadcast-sql-brute,banner,ssl-cert',
  'remote-access': 'ssh-hostkey,sshv1,rdp-enum-encryption,banner,ssl-cert',
  'comprehensive': 'default,safe'
};

export interface OSMatch {
  name: string;
  accuracy: number;
  os_class?: any[];
}

export interface HostInfo {
  os_matches?: OSMatch[];
  mac_address?: string;
  mac_vendor?: string;
  state?: string;
  reason?: string;
  uptime?: {
    seconds: number;
    lastboot: string;
  };
  distance?: number;
  hostnames?: string[];
}

export interface ScanResult {
  host: string;
  port: number;
  state: string;
  service: string;
  version: string;
  cpes?: string[];
  cves?: any[];
}

export interface TargetInfo {
  original: string;
  normalized: string;
  hosts_count: number | null;
  target_type: string;
  warnings: string[];
}

export interface ScanResponse {
  results: ScanResult[];
  nmap_cmd: string;
  nmap_output: string;
  host_info?: HostInfo | null;
  target_info?: TargetInfo;
  error?: string;
}

export const executeScan = async (
  target: string,
  scanDepth: DepthKey,
  scanProfile: ProfileKey
): Promise<{ results: ScanResult[], nmapCmd: string, nmapOutput: string, hostInfo?: HostInfo | null, targetInfo?: TargetInfo }> => {
  const depthArgs = scanDepthMapping[scanDepth] ?? scanDepthMapping['fast'];
  const profileArgs = scanProfilePorts[scanProfile] ?? scanProfilePorts['comprehensive'];
  const nmapArgs = `${depthArgs} ${profileArgs}`;

  console.log('Starting scan with args:', nmapArgs);

  // Use environment variable or fallback to localhost
  const backendBaseUrl = import.meta.env.VITE_BACKEND_URL || 'http://localhost:8000';
  const backendUrl = `${backendBaseUrl}/api/scan`;
  
  console.log('🔗 Connecting to backend:', backendUrl);
  
  const response = await fetch(backendUrl, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      ip_address: target,
      nmap_args: nmapArgs,
      scan_profile: scanProfile
    })
  });

  if (!response.ok) {
    const errorText = await response.text();
    throw new Error(`Scan failed: ${response.status} - ${errorText}`);
  }

  const scanData: ScanResponse = await response.json();
  console.log('✅ INITIAL SCAN COMMAND:', scanData.nmap_cmd);
  console.log('✅ Nmap args sent to backend:', nmapArgs);
  console.log('📊 Scan results:', scanData.results);

  // Skip follow-up scans for subnet/CIDR scans (e.g., 192.168.1.0/24)
  const isSubnetScan = target.includes('/');
  
  // Check for services with unknown versions and run follow-up scans (only for single host scans)
  const unknownServices = scanData.results.filter(s => !s.version || s.version.toLowerCase() === 'unknown');
  
  if (unknownServices.length > 0 && !isSubnetScan) {
    console.log(`Found ${unknownServices.length} services with unknown version, running follow-up scans...`);
    
    for (const service of unknownServices) {
      const followupArgs = `-sV -p ${service.port} --script ${profileExtraScripts[scanProfile]}`;
      
      try {
        const followupResponse = await fetch(backendUrl, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            ip_address: service.host,
            nmap_args: followupArgs,
            scan_profile: scanProfile,
            follow_up: true
          })
        });

        if (followupResponse.ok) {
          const followupData: ScanResponse = await followupResponse.json();
          
          // Update the original result with new version info
          const originalIndex = scanData.results.findIndex(
            r => r.host === service.host && r.port === service.port
          );
          
          if (originalIndex >= 0 && followupData.results.length > 0) {
            const updatedService = followupData.results[0];
            if (updatedService.version && updatedService.version !== 'unknown') {
              scanData.results[originalIndex].version = updatedService.version;
            }
            if (updatedService.cves && updatedService.cves.length > 0) {
              scanData.results[originalIndex].cves = updatedService.cves;
            }
          }
        }
      } catch (error) {
        console.error(`Follow-up scan failed for ${service.host}:${service.port}`, error);
      }
    }
  }

  return {
    results: scanData.results,
    nmapCmd: scanData.nmap_cmd,
    nmapOutput: scanData.nmap_output,
    hostInfo: scanData.host_info,
    targetInfo: scanData.target_info
  };
};
