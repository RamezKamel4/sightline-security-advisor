import { supabase } from "@/integrations/supabase/client";

interface CVEDetail {
  cve_id: string;
  title: string;
  description: string;
  cvss_score: number | null;
}

export const enrichFindingsWithCVE = async (scanId: string): Promise<void> => {
  console.log('🔍 Starting CVE enrichment for scan:', scanId);
  
  // Check if this scan has already been enriched
  const { data: scanData, error: scanCheckError } = await supabase
    .from('scans')
    .select('cve_enriched')
    .eq('scan_id', scanId)
    .single();

  if (scanCheckError) {
    console.error('❌ Error checking scan enrichment status:', scanCheckError);
    throw new Error(`Failed to check scan status: ${scanCheckError.message}`);
  }

  if (scanData?.cve_enriched) {
    console.log('✅ Scan already enriched, skipping CVE lookup');
    return;
  }
  
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
      // Build smart search query for NVD
      // If service_version contains a product name (e.g., "Apache httpd 2.4.7"), use it directly
      // Otherwise combine service_name and service_version
      let searchQuery = '';
      
      if (finding.service_version && finding.service_version !== 'unknown') {
        // Check if service_version already contains a recognizable product name
        const productPatterns = [
          /^(Apache\s+(?:httpd|Tomcat))\s+(\d+[\d.]*)/i,
          /^(nginx)\s+(\d+[\d.]*)/i,
          /^(Microsoft\s+IIS)\s+(\d+[\d.]*)/i,
          /^(OpenSSH)[_\s]+(\d+[\d.]*)/i,
          /^(lighttpd)\s+(\d+[\d.]*)/i,
          /^(Eclipse\s+Jetty)\s+(\d+[\d.]*)/i,
        ];
        
        let matched = false;
        for (const pattern of productPatterns) {
          const match = finding.service_version.match(pattern);
          if (match) {
            // Use the extracted product and version directly
            searchQuery = `${match[1]} ${match[2]}`;
            matched = true;
            break;
          }
        }
        
        if (!matched) {
          // Fallback: if service_version looks like "product version", use it directly
          // Otherwise combine service_name with service_version
          if (/^[a-zA-Z]/.test(finding.service_version) && /\d/.test(finding.service_version)) {
            searchQuery = finding.service_version;
          } else {
            searchQuery = `${finding.service_name} ${finding.service_version}`;
          }
        }
      } else {
        searchQuery = finding.service_name;
      }
      
      console.log(`🔎 Querying NVD for: "${searchQuery}" (from service: ${finding.service_name}, version: ${finding.service_version || 'unknown'})`);

      // Call nvd-proxy edge function with keywordSearch parameter
      const nvdUrl = `https://bliwnrikjfzcialoznur.supabase.co/functions/v1/nvd-proxy?keywordSearch=${encodeURIComponent(searchQuery)}`;
      
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

  // Mark scan as enriched
  const { error: updateError } = await supabase
    .from('scans')
    .update({ cve_enriched: true })
    .eq('scan_id', scanId);

  if (updateError) {
    console.error('❌ Error marking scan as enriched:', updateError);
    // Don't throw - enrichment was successful even if we couldn't update the flag
  }

  console.log('✅ CVE enrichment completed and marked in database');
};
