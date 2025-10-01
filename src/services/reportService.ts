
import { supabase } from '@/integrations/supabase/client';
import { enrichFindingsWithCVE } from './cveEnrichmentService';

export const generateReport = async (scanId: string): Promise<void> => {
  console.log('🚀 Starting report generation for scan:', scanId);
  
  try {
    // Step 1: Enrich findings with CVE data from NVD
    console.log('🔍 Enriching findings with CVE data from NVD...');
    await enrichFindingsWithCVE(scanId);
    console.log('✅ CVE enrichment completed');
    
    // Step 2: Generate AI report with enriched data
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
