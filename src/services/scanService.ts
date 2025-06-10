
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

// Map scan depth to actual nmap arguments
const scanDepthMapping: Record<string, string> = {
  'fast': '-T4 --top-ports 1000',
  'deep': '-T4 -sV -O',
  'aggressive': '-T4 -A -sC -sV --script vuln'
};

export const createScan = async (scanData: ScanRequest): Promise<string> => {
  console.log('🚀 Starting createScan with data:', scanData);
  
  const { data: { user } } = await supabase.auth.getUser();
  
  if (!user) {
    console.error('❌ User not authenticated');
    throw new Error('User not authenticated');
  }

  console.log('✅ User authenticated:', user.id);

  // Create scan record in database
  console.log('💾 Creating scan record in database...');
  const { data: scan, error } = await supabase
    .from('scans')
    .insert({
      target: scanData.target,
      profile: scanData.scanProfile, // Use the profile directly from frontend
      scan_depth: scanData.scanDepth,
      status: 'running',
      start_time: new Date().toISOString(),
      user_id: user.id
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
    // Get the nmap arguments based on scan depth
    const nmapArgs = scanDepthMapping[scanData.scanDepth] || '-T4';
    
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
        ip: scanData.target,
        nmap_args: nmapArgs,
        scan_profile: scanData.scanProfile
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
    
    // Update scan status to completed
    console.log('💾 Updating scan status to completed...');
    await supabase
      .from('scans')
      .update({
        status: 'completed',
        end_time: new Date().toISOString()
      })
      .eq('scan_id', scan.scan_id);

    // Store findings
    console.log('💾 Storing', scanResults.length, 'findings...');
    for (const result of scanResults) {
      const { error: findingError } = await supabase
        .from('findings')
        .insert({
          scan_id: scan.scan_id,
          port: result.port,
          service_name: result.service,
          service_version: result.version,
          cve_id: result.cves.length > 0 ? result.cves[0].id : null
        });
      
      if (findingError) {
        console.error('❌ Error storing finding:', findingError);
      }
    }

    console.log('🎉 Scan completed successfully:', scan.scan_id);
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

export const generateReport = async (scanId: string): Promise<void> => {
  console.log('🚀 Starting report generation for scan:', scanId);
  
  try {
    console.log('📡 Calling generate-report edge function...');
    
    // Call the edge function to generate AI report
    const { data, error } = await supabase.functions.invoke('generate-report', {
      body: { scanId }
    });

    console.log('📋 Edge function response received:', { data, error });

    if (error) {
      console.error('❌ Edge function error details:', error);
      
      // Extract meaningful error message
      let errorMessage = 'Failed to generate report';
      
      if (typeof error === 'string') {
        errorMessage = error;
      } else if (error.message) {
        errorMessage = error.message;
      } else if (error.context?.error) {
        errorMessage = error.context.error;
      }
      
      throw new Error(errorMessage);
    }

    // Check if the response indicates success
    if (data && data.error) {
      console.error('❌ Error in response data:', data.error);
      throw new Error(data.error);
    }

    console.log('✅ Edge function completed successfully');

    // Verify report was actually created in database
    console.log('🔍 Verifying report creation in database...');
    const { data: report, error: dbError } = await supabase
      .from('reports')
      .select('*')
      .eq('scan_id', scanId)
      .maybeSingle();

    if (dbError) {
      console.error('❌ Database verification error:', dbError);
      throw new Error('Failed to verify report creation in database');
    }

    if (!report) {
      console.error('❌ Report not found in database after generation');
      throw new Error('Report was not created successfully - not found in database');
    }

    console.log('🎉 Report generated and verified successfully:', report.report_id);
  } catch (error) {
    console.error('💥 Report generation failed:', error);
    
    // Re-throw with a user-friendly message
    const friendlyMessage = error instanceof Error 
      ? error.message 
      : 'An unexpected error occurred during report generation';
    
    throw new Error(friendlyMessage);
  }
};
