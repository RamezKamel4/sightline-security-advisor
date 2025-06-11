
// Map scan depth to timing and detection arguments
const scanDepthMapping: Record<string, string> = {
  'fast': '-T4',
  'deep': '-T4 -sV -O',
  'aggressive': '-T4 -A -sC -sV --script vuln'
};

// Map scan profiles to specific port ranges and targets
const scanProfileMapping: Record<string, string> = {
  'web-apps': '-p 80,443,8080,8443,3000,5000,8000,9000',
  'databases': '-p 3306,5432,1433,1521,27017,6379,11211,9042',
  'remote-access': '-p 22,3389,5900,1194,1723,4899,5800,5801',
  'comprehensive': '--top-ports 1000'
};

export interface ScanResult {
  port: number;
  service: string;
  version: string;
  cves: any[];
}

export const executeScan = async (target: string, scanDepth: string, scanProfile: string): Promise<ScanResult[]> => {
  // Get the nmap arguments based on scan depth
  const depthArgs = scanDepthMapping[scanDepth] || '-T4';
  
  // Get the port specification based on scan profile
  const profileArgs = scanProfileMapping[scanProfile] || '--top-ports 1000';
  
  // Combine depth and profile arguments
  const nmapArgs = `${depthArgs} ${profileArgs}`;
  
  console.log('🔍 Starting backend scan with args:', nmapArgs);
  console.log('📋 Scan profile:', scanProfile, '- targeting:', profileArgs);

  // Try to connect to local FastAPI backend
  const backendUrl = 'http://localhost:8000/api/scan';
  console.log('🌐 Connecting to backend at:', backendUrl);
  
  const response = await fetch(backendUrl, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({ 
      ip_address: target,
      nmap_args: nmapArgs,
      scan_profile: scanProfile
    }),
  });

  console.log('📡 Backend response status:', response.status);

  if (!response.ok) {
    const errorText = await response.text();
    console.error('❌ Backend error response:', errorText);
    throw new Error(`Backend scan failed: ${response.status} - ${errorText}`);
  }

  const scanResults: ScanResult[] = await response.json();
  console.log('✅ Scan results received:', scanResults.length, 'services found');
  
  return scanResults;
};
