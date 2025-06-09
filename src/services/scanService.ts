
import { supabase } from '@/integrations/supabase/client';

export interface ScanResult {
  port: number;
  service: string;
  version: string;
  cves: any[];
}

export interface ScanRequest {
  target: string;
  scanProfile: string;
  scanDepth: string;
  username?: string;
  password?: string;
  schedule: string;
}

export const createScan = async (scanData: ScanRequest): Promise<string> => {
  const { data: { user } } = await supabase.auth.getUser();
  
  if (!user) {
    throw new Error('User not authenticated');
  }

  // Create scan record in database
  const { data: scan, error } = await supabase
    .from('scans')
    .insert({
      target: scanData.target,
      profile: scanData.scanProfile,
      scan_depth: scanData.scanDepth,
      status: 'running',
      start_time: new Date().toISOString(),
      user_id: user.id
    })
    .select()
    .single();

  if (error) {
    console.error('Error creating scan:', error);
    throw new Error('Failed to create scan');
  }

  // Start the actual scan
  try {
    const response = await fetch('http://localhost:8000/api/scan', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({ ip: scanData.target }),
    });

    if (!response.ok) {
      throw new Error('Scan failed');
    }

    const scanResults: ScanResult[] = await response.json();
    
    // Update scan status to completed
    await supabase
      .from('scans')
      .update({
        status: 'completed',
        end_time: new Date().toISOString()
      })
      .eq('scan_id', scan.scan_id);

    // Store findings
    for (const result of scanResults) {
      await supabase
        .from('findings')
        .insert({
          scan_id: scan.scan_id,
          port: result.port,
          service_name: result.service,
          service_version: result.version,
          cve_id: result.cves.length > 0 ? result.cves[0].id : null
        });
    }

    console.log('Scan completed successfully:', scan.scan_id);
    return scan.scan_id;
  } catch (error) {
    // Update scan status to failed
    await supabase
      .from('scans')
      .update({
        status: 'failed',
        end_time: new Date().toISOString()
      })
      .eq('scan_id', scan.scan_id);
    
    throw error;
  }
};

export const generateReport = async (scanId: string): Promise<void> => {
  // Call the edge function to generate AI report
  const { data, error } = await supabase.functions.invoke('generate-report', {
    body: { scanId }
  });

  if (error) {
    console.error('Error generating report:', error);
    throw new Error('Failed to generate report');
  }

  console.log('Report generated successfully');
};
