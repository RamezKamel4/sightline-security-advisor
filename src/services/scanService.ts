
import { supabase } from '@/integrations/supabase/client';
import { executeScan, type ScanResult, type CVEInfo } from './scanApi';

export interface ScanRequest {
  target: string;
  scanProfile: string;
  username?: string;
  password?: string;
}

export const createScan = async (scanData: ScanRequest): Promise<string> => {
  console.log('🚀 Starting createScan with data:', scanData);
  
  const { data: { user } } = await supabase.auth.getUser();
  
  if (!user) {
    console.error('❌ User not authenticated');
    throw new Error('User not authenticated');
  }

  console.log('✅ User authenticated:', user.id);

  // Create and execute scan immediately
  console.log('💾 Creating scan record in database...');
  
  // Store both original and normalized target
  const userInputTarget = scanData.target;
  let normalizedTarget = userInputTarget;
  
  const { data: scan, error } = await supabase
    .from('scans')
    .insert({
      target: scanData.target,
      user_input_target: userInputTarget,
      normalized_target: normalizedTarget,
      profile: scanData.scanProfile,
      status: 'running',
      start_time: new Date().toISOString(),
      user_id: user.id,
      host_info: null  // Will be populated after scan completes
    })
    .select()
    .single();

  if (error) {
    console.error('❌ Database error creating scan:', error);
    throw new Error(`Failed to create scan: ${error.message}`);
  }

  console.log('✅ Scan created in database with ID:', scan.scan_id);

  // Start the actual scan
  try {
    const scanResponse = await executeScan(
      scanData.target, 
      'fast', // Always use fast scan
      scanData.scanProfile as 'web-apps' | 'databases' | 'remote-access' | 'comprehensive'
    );
    
    // Extract target info from backend response if available
    if (scanResponse.targetInfo) {
      normalizedTarget = scanResponse.targetInfo.normalized;
    }
    
    // Update scan status to completed and store nmap command + host info
    console.log('💾 Updating scan status to completed...');
    console.log('📝 Command to be saved:', scanResponse.nmapCmd);
    await supabase
      .from('scans')
      .update({
        status: 'completed',
        end_time: new Date().toISOString(),
        nmap_cmd: scanResponse.nmapCmd,
        nmap_output: scanResponse.nmapOutput,
        host_info: scanResponse.hostInfo as any || null,
        normalized_target: normalizedTarget,
        estimated_hosts: scanResponse.targetInfo?.hosts_count || 1
      })
      .eq('scan_id', scan.scan_id);

    // Store findings
    console.log('💾 Storing', scanResponse.results.length, 'findings...');
    await storeFindings(scan.scan_id, scanResponse.results);

    console.log('🎉 Scan completed successfully:', scan.scan_id);
    console.log('ℹ️ CVE enrichment will be performed when report is generated');
    return scan.scan_id;
  } catch (error) {
    console.error('❌ Scan execution error:', error);
    
    // Update scan status to failed - ensure this always happens
    try {
      const { error: updateError } = await supabase
        .from('scans')
        .update({
          status: 'failed',
          end_time: new Date().toISOString()
        })
        .eq('scan_id', scan.scan_id);
      
      if (updateError) {
        console.error('❌ Failed to update scan status:', updateError);
      }
    } catch (updateErr) {
      console.error('❌ Exception updating scan status:', updateErr);
    }
    
    // If it's a network error, provide helpful message
    if (error instanceof TypeError && error.message.includes('fetch')) {
      throw new Error('Cannot connect to scan backend. Make sure the Python FastAPI server is running on localhost:8000');
    }
    
    throw error;
  }
};

const storeFindings = async (scanId: string, scanResults: ScanResult[]): Promise<void> => {
  console.log('📝 Preparing to store findings:', scanResults.map(r => `${r.host}:${r.port}/${r.service} (${r.state})`).join(', '));
  
  // First, store any CVEs from the backend (only for services WITH versions)
  const cveMap = new Map<string, string>(); // Maps finding key to cve_id
  
  for (const result of scanResults) {
    // GATING: Only store CVEs if service has a detected version
    const hasVersion = result.version && 
                       result.version.toLowerCase() !== 'unknown' && 
                       result.version.trim() !== '';
    
    if (!hasVersion) {
      console.log(`🚫 Skipping CVE storage for ${result.service} - no version detected`);
      continue;
    }
    
    if (result.cves && result.cves.length > 0) {
      const bestCve = result.cves[0]; // Take the first/most relevant CVE
      const cveId = bestCve.id; // Backend uses "id" not "cve_id"
      
      console.log(`💾 Storing CVE ${cveId} for ${result.service} ${result.version}`);
      
      // Upsert CVE into the cve table
      const { error: cveError } = await supabase
        .from('cve')
        .upsert({
          cve_id: cveId,
          title: bestCve.title || cveId,
          description: bestCve.description || 'No description available',
          cvss_score: bestCve.cvss, // Backend uses "cvss" not "cvss_score"
          confidence: bestCve.confidence || 'high'
        }, { onConflict: 'cve_id' });
      
      if (cveError) {
        console.error(`❌ Error storing CVE ${cveId}:`, cveError);
      } else {
        console.log(`✅ CVE ${cveId} stored successfully`);
        cveMap.set(`${result.host}:${result.port}`, cveId);
      }
    }
  }
  
  // Now store findings with CVE references
  const findingsToInsert = scanResults.map(result => {
    const cveId = cveMap.get(`${result.host}:${result.port}`) || null;
    return {
      scan_id: scanId,
      host: result.host,
      port: result.port,
      state: result.state,
      service_name: result.service,
      service_version: result.version || 'unknown',
      cve_id: cveId,
      confidence: result.confidence || 0,
      raw_banner: result.raw_banner || null,
      headers: result.headers || null,
      tls_info: result.tls_info || null,
      proxy_detection: result.proxy_detection || null,
      detection_methods: result.detection_methods || null,
    };
  });

  const { data, error: findingError } = await supabase
    .from('findings')
    .insert(findingsToInsert)
    .select();
  
  if (findingError) {
    console.error('❌ Error storing findings:', findingError);
    throw new Error(`Failed to store findings: ${findingError.message}`);
  }
  
  console.log('✅ Successfully stored', data?.length || 0, 'findings');
  if (cveMap.size > 0) {
    console.log(`🎯 ${cveMap.size} findings linked to CVEs from backend`);
  }
};

// Re-export report generation for backwards compatibility
export { generateReport } from './reportService';
