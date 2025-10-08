
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

  // Create scan record in database - the scan_id will be auto-generated with the new format
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
    
    // Update scan status to failed
    await supabase
      .from('scans')
      .update({
        status: 'failed',
        end_time: new Date().toISOString()
      })
      .eq('scan_id', scan.scan_id);
    
    // If it's a network error, provide helpful message
    if (error instanceof TypeError && error.message.includes('fetch')) {
      throw new Error('Cannot connect to scan backend. Make sure the Python FastAPI server is running on localhost:8000');
    }
    
    throw error;
  }
};

const storeFindings = async (scanId: string, scanResults: ScanResult[]): Promise<void> => {
  for (const result of scanResults) {
    const { error: findingError } = await supabase
      .from('findings')
      .insert({
        scan_id: scanId,
        port: result.port,
        service_name: result.service,
        service_version: result.version,
        cve_id: result.cves.length > 0 ? result.cves[0].id : null
      });
    
    if (findingError) {
      console.error('❌ Error storing finding:', findingError);
    }
  }
};

// Re-export report generation for backwards compatibility
export { generateReport } from './reportService';
