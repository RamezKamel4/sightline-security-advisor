import { supabase } from "@/integrations/supabase/client";

interface CVEDetail {
  cve_id: string;
  title: string;
  description: string;
  cvss_score: number | null;
}

export const enrichFindingsWithCVE = async (scanId: string): Promise<void> => {
  console.log('🔍 Starting CVE enrichment for scan:', scanId);
  
  // Get all findings for this scan
  const { data: findings, error: findingsError } = await supabase
    .from('findings')
    .select('*')
    .eq('scan_id', scanId);

  if (findingsError) {
    console.error('❌ Error fetching findings:', findingsError);
    throw new Error(`Failed to fetch findings: ${findingsError.message}`);
  }

  if (!findings || findings.length === 0) {
    console.log('ℹ️ No findings to enrich');
    return;
  }

  console.log(`📊 Found ${findings.length} findings to enrich`);

  // Get session for authorization
  const { data: { session } } = await supabase.auth.getSession();
  if (!session) {
    throw new Error('Not authenticated');
  }

  // For each finding, query NVD API for CVEs
  for (const finding of findings) {
    try {
      console.log(`🔎 Querying NVD for: ${finding.service_name} ${finding.service_version || ''}`);
      
      // Build search query for NVD
      const searchQuery = finding.service_version 
        ? `${finding.service_name} ${finding.service_version}`
        : finding.service_name;

      // Call nvd-proxy edge function
      const nvdUrl = `https://bliwnrikjfzcialoznur.supabase.co/functions/v1/nvd-proxy?cpeName=${encodeURIComponent(searchQuery)}`;
      
      const response = await fetch(nvdUrl, {
        method: 'GET',
        headers: {
          'Authorization': `Bearer ${session.access_token}`,
          'Content-Type': 'application/json',
        },
      });

      if (!response.ok) {
        console.warn(`⚠️ NVD lookup failed for ${finding.service_name}: ${response.status}`);
        continue;
      }

      const nvdData = await response.json();
      const vulnerabilities = nvdData.vulnerabilities || [];

      console.log(`✅ Found ${vulnerabilities.length} CVEs for ${finding.service_name}`);

      // Store CVE data if found
      if (vulnerabilities.length > 0) {
        const cve = vulnerabilities[0].cve;
        const cveId = cve.id;
        
        // Extract description
        const description = cve.descriptions?.find((d: any) => d.lang === 'en')?.value || 'No description available';
        
        // Extract CVSS score
        let cvssScore = null;
        if (cve.metrics?.cvssMetricV31) {
          cvssScore = cve.metrics.cvssMetricV31[0]?.cvssData?.baseScore;
        } else if (cve.metrics?.cvssMetricV30) {
          cvssScore = cve.metrics.cvssMetricV30[0]?.cvssData?.baseScore;
        } else if (cve.metrics?.cvssMetricV2) {
          cvssScore = cve.metrics.cvssMetricV2[0]?.cvssData?.baseScore;
        }

        // Store in CVE table
        const { error: cveError } = await supabase
          .from('cve')
          .upsert({
            cve_id: cveId,
            title: cveId,
            description: description,
            cvss_score: cvssScore
          }, {
            onConflict: 'cve_id'
          });

        if (cveError) {
          console.error(`❌ Error storing CVE ${cveId}:`, cveError);
        } else {
          console.log(`💾 Stored CVE: ${cveId} (CVSS: ${cvssScore})`);
        }

        // Update finding with CVE ID
        const { error: updateError } = await supabase
          .from('findings')
          .update({ cve_id: cveId })
          .eq('finding_id', finding.finding_id);

        if (updateError) {
          console.error(`❌ Error updating finding with CVE:`, updateError);
        }
      }
      
      // Add delay to respect rate limits
      await new Promise(resolve => setTimeout(resolve, 1000));
      
    } catch (error) {
      console.error(`❌ Error enriching finding ${finding.finding_id}:`, error);
      // Continue with next finding
    }
  }

  console.log('✅ CVE enrichment completed');
};
