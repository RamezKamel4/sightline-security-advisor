
// Map scan depth to actual nmap arguments
const scanDepthMapping: Record<string, string> = {
  'fast': '-T4 --top-ports 1000',
  'deep': '-T4 -sV -O',
  'aggressive': '-T4 -A -sC -sV --script vuln'
};

export interface ScanResult {
  port: number;
  service: string;
  version: string;
  cves: any[];
}

export const executeScan = async (target: string, scanDepth: string, scanProfile: string): Promise<ScanResult[]> => {
  // Get the nmap arguments based on scan depth
  const nmapArgs = scanDepthMapping[scanDepth] || '-T4';
  
  console.log('🔍 Starting backend scan with args:', nmapArgs);

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
