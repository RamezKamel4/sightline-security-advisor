
import { supabase } from '@/integrations/supabase/client';
import { executeScan, type ScanResult } from './scanApi';

export interface ScanRequest {
  target: string;
  scanProfile: string;
  scanDepth: string;
  username?: string;
  password?: string;
  schedule: string;
}

export const createScan = async (scanData: ScanRequest): Promise<string> => {
  console.log('🚀 Starting createScan with data:', scanData);
  
  const { data: { user } } = await supabase.auth.getUser();
  
  if (!user) {
    console.error('❌ User not authenticated');
    throw new Error('User not authenticated');
  }

  console.log('✅ User authenticated:', user.id);

  // Check if this is a scheduled scan
  if (scanData.schedule !== 'now') {
    console.log('📅 Creating scheduled scan for:', scanData.schedule);
    
    // Calculate the next run time based on current time and frequency
    const now = new Date();
    const scheduledTime = now.toTimeString().split(' ')[0].substring(0, 5); // HH:MM format
    
    const { data: scheduledScan, error: scheduleError } = await supabase
      .from('scheduled_scans')
      .insert({
        user_id: user.id,
        target: scanData.target,
        profile: scanData.scanProfile,
        scan_depth: scanData.scanDepth,
        frequency: scanData.schedule,
        scheduled_time: scheduledTime,
        next_run_at: now.toISOString(),
        is_active: true
      })
      .select()
      .single();

    if (scheduleError) {
      console.error('❌ Error creating scheduled scan:', scheduleError);
      throw new Error(`Failed to create scheduled scan: ${scheduleError.message}`);
    }

    console.log('✅ Scheduled scan created:', scheduledScan.id);
    return scheduledScan.id;
  }

  // For immediate scans, proceed as before
  console.log('💾 Creating scan record in database...');
  const { data: scan, error } = await supabase
    .from('scans')
    .insert({
      target: scanData.target,
      profile: scanData.scanProfile,
      scan_depth: scanData.scanDepth,
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
      scanData.scanDepth as 'fast' | 'deep' | 'aggressive', 
      scanData.scanProfile as 'web-apps' | 'databases' | 'remote-access' | 'comprehensive'
    );
    
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
        host_info: scanResponse.hostInfo as any || null
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
  
  const findingsToInsert = scanResults.map(result => ({
    scan_id: scanId,
    host: result.host,
    port: result.port,
    state: result.state,
    service_name: result.service,
    service_version: result.version || 'unknown',
    cve_id: null,  // CVE enrichment will happen during report generation
    confidence: (result as any).confidence || 0,
    raw_banner: (result as any).raw_banner || null,
    headers: (result as any).headers || null,
    tls_info: (result as any).tls_info || null,
    proxy_detection: (result as any).proxy_detection || null,
    detection_methods: (result as any).detection_methods || null,
  }));

  const { data, error: findingError } = await supabase
    .from('findings')
    .insert(findingsToInsert)
    .select();
  
  if (findingError) {
    console.error('❌ Error storing findings:', findingError);
    throw new Error(`Failed to store findings: ${findingError.message}`);
  }
  
  console.log('✅ Successfully stored', data?.length || 0, 'findings');
};

// Re-export report generation for backwards compatibility
export { generateReport } from './reportService';
