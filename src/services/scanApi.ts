// scanAPI.ts (improved)
type DepthKey = 'fast' | 'deep' | 'aggressive';
type ProfileKey = 'web-apps' | 'databases' | 'remote-access' | 'comprehensive';

const scanDepthMapping: Record<DepthKey, string> = {
  // fast: quick timing, still include top-level service detection for better results
  'fast': '-T4 -sV --version-intensity 1',
  // deep: stronger version detection and OS detection
  'deep': '-T4 -sV --version-all -O --version-intensity 5',
  // aggressive: full fingerprinting + vuln scripts (use with caution on production networks)
  'aggressive': '-T4 -A -sC -sV --script vuln --version-intensity 5'
};

// keep the simple port mappings, but add recommended extra scripts per profile
const scanProfilePorts: Record<ProfileKey, string> = {
  'web-apps': '-p 80,443,8080,8443,3000,5000,8000,9000',
  'databases': '-p 3306,5432,1433,1521,27017,6379,11211,9042',
  'remote-access': '-p 22,3389,5900,1194,1723,4899,5800,5801',
  'comprehensive': '--top-ports 1000'
};

// NSE scripts to add for better product/version detection per profile (appended to nmap args during follow-up scans)
const profileExtraScripts: Record<ProfileKey, string> = {
  'web-apps': '--script http-enum,http-headers,http-title,ssl-cert,banner',
  'databases': '--script broadcast-sql-brute,banner,ssl-cert', // use carefully
  'remote-access': '--script ssh-hostkey,sshv1,rdp-enum-encryption,banner,ssl-cert',
  'comprehensive': '--script "default and safe"'
};

export interface ScanResult {
  host: string;
  port: number;
  service: string;   // e.g. 'http'
  version: string;   // e.g. 'nginx/1.18.0' or 'unknown'
  cpes?: string[];   // optional if returned by backend
  cves?: any[];      // vulnerability list
}

// helper: fetch with timeout + retries
async function fetchWithRetry(url: string, options: RequestInit = {}, retries = 2, timeoutMs = 60000): Promise<Response> {
  for (let attempt = 0; attempt <= retries; attempt++) {
    const controller = new AbortController();
    const id = setTimeout(() => controller.abort(), timeoutMs);
    try {
      const resp = await fetch(url, { ...options, signal: controller.signal });
      clearTimeout(id);
      if (!resp.ok && (resp.status === 429 || resp.status >= 500) && attempt < retries) {
        // simple backoff
        await new Promise(r => setTimeout(r, 1000 * (attempt + 1)));
        continue;
      }
      return resp;
    } catch (err) {
      clearTimeout(id);
      if (attempt < retries) {
        await new Promise(r => setTimeout(r, 1000 * (attempt + 1)));
        continue;
      }
      throw err;
    }
  }
  throw new Error('fetchWithRetry exhausted');
}

// main function
export const executeScan = async (target: string, scanDepth: DepthKey, scanProfile: ProfileKey): Promise<ScanResult[]> => {
  // Compose base args
  const depthArgs = scanDepthMapping[scanDepth] ?? scanDepthMapping['fast'];
  const profileArgs = scanProfilePorts[scanProfile] ?? scanProfilePorts['comprehensive'];
  const nmapArgs = `${depthArgs} ${profileArgs}`;

  console.log('🔍 Starting backend scan with args:', nmapArgs);
  console.log('📋 Scan profile:', scanProfile, '- targeting:', profileArgs);

  const backendUrl = 'http://localhost:8000/api/scan';
  console.log('🌐 Connecting to backend at:', backendUrl);

  // initial scan request
  const initResp = await fetchWithRetry(backendUrl, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      ip_address: target,
      nmap_args: nmapArgs,
      scan_profile: scanProfile
    })
  }, 3, 120000);

  console.log('📡 Backend response status:', initResp.status);
  if (!initResp.ok) {
    const errorText = await initResp.text();
    console.error('❌ Backend error response:', errorText);
    throw new Error(`Backend scan failed: ${initResp.status} - ${errorText}`);
  }

  let scanResults: ScanResult[] = await initResp.json();
  console.log('✅ Initial scan results received:', scanResults.length, 'services found');

  // Identify services with unknown version to run targeted follow-up scans
  const unknowns = scanResults.filter(s => !s.version || s.version.toLowerCase() === 'unknown');

  if (unknowns.length > 0) {
    console.log(`🔎 Found ${unknowns.length} services with unknown version — running follow-up banner/version detection scans...`);

    // group follow-ups by host to minimize repeated host scans
    const followupsByHost: Record<string, { ports: number[]; services: string[] }> = {};
    for (const s of unknowns) {
      followupsByHost[s.host] = followupsByHost[s.host] || { ports: [], services: [] };
      followupsByHost[s.host].ports.push(s.port);
      followupsByHost[s.host].services.push(s.service);
    }

    // sequentially run followups (avoid flooding backend)
    for (const host of Object.keys(followupsByHost)) {
      const ports = followupsByHost[host].ports.join(',');
      // choose better scripts for profile
      const extraScripts = profileExtraScripts[scanProfile] || '';
      // follow-up args: keep -sV and add profile-specific scripts
      const followupArgs = `-sV --version-intensity 5 -p ${ports} ${extraScripts}`;
      console.log(`🔁 Follow-up scan for ${host} ports ${ports} using: ${followupArgs}`);

      // POST follow-up to same endpoint (backend must accept single-host scans)
      try {
        const followResp = await fetchWithRetry(backendUrl, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            ip_address: host,
            nmap_args: followupArgs,
            scan_profile: scanProfile,
            follow_up: true
          })
        }, 3, 120000);

        if (!followResp.ok) {
          console.warn(`⚠️ Follow-up scan failed for ${host}:`, await followResp.text());
          continue;
        }

        const followResults: ScanResult[] = await followResp.json();
        console.log(`🔄 Follow-up returned ${followResults.length} service entries for ${host}`);

        // Merge follow-up results into main results (update version/cpes/cves for matching port)
        for (const fr of followResults) {
          const idx = scanResults.findIndex(r => r.host === fr.host && r.port === fr.port);
          if (idx >= 0) {
            // prefer non-empty version & add new cpes/cves if provided
            if (fr.version && fr.version.toLowerCase() !== 'unknown') {
              scanResults[idx].version = fr.version;
            }
            if (fr.cpes && fr.cpes.length) {
              scanResults[idx].cpes = fr.cpes;
            }
            if (fr.cves && fr.cves.length) {
              // merge and dedupe by CVE id if possible
              const existing = scanResults[idx].cves || [];
              const merged = [...existing];
              for (const c of fr.cves) {
                const cveId = (c?.cveId || c?.id || c?.CVE) as string | undefined;
                const exists = existing.some((e: any) => (e?.cveId || e?.id || e?.CVE) === cveId);
                if (!exists) merged.push(c);
              }
              scanResults[idx].cves = merged;
            }
          } else {
            // new entry — push it
            scanResults.push(fr);
          }
        }
      } catch (err) {
        console.error('❌ Error during follow-up scan for', host, err);
      }

      // polite delay between follow-up host scans
      await new Promise(r => setTimeout(r, 500));
    }
  } else {
    console.log('🔎 No unknown-version services found — no follow-ups needed.');
  }

  console.log('✅ Final merged scan results count:', scanResults.length);
  return scanResults;
};
