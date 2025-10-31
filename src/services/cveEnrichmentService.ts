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
      // Skip generic/non-specific services that won't have CVEs
      const skipServices = ['http', 'https', 'http-alt', 'https-alt', 'http-proxy', 'cslistener', 'upnp', 'unknown'];
      if (skipServices.includes(finding.service_name.toLowerCase())) {
        console.log(`⏭️ Skipping generic service: ${finding.service_name}`);
        continue;
      }

      // Skip if version is unknown and service is too generic
      if (!finding.service_version || finding.service_version === 'unknown') {
        console.log(`⏭️ Skipping ${finding.service_name} - no version information`);
        continue;
      }

      console.log(`🔎 Querying NVD for: ${finding.service_name} ${finding.service_version}`);
      
      // Extract product name from service_name
      // Examples: "http Apache httpd" -> "Apache", "OpenSSH" -> "OpenSSH", "MySQL" -> "MySQL"
      let productName = finding.service_name;
      
      // Remove common protocol prefixes
      productName = productName.replace(/^(http|https|ssh|ftp|smtp|mysql|postgresql)\s+/i, '');
      
      // Extract first word after protocol (usually the vendor/product name)
      const words = productName.trim().split(/\s+/);
      productName = words[0] || finding.service_name;
      
      // Build search queries to try (in order of priority)
      const searchQueries = [
        `${productName} ${finding.service_version}`, // e.g., "Apache 2.4.62"
        `${finding.service_name} ${finding.service_version}`, // e.g., "http Apache 2.4.62"
      ];
      
      let vulnerabilities: any[] = [];
      let successfulQuery = '';
      
      // Try each search query until we get results
      for (const searchQuery of searchQueries) {
        console.log(`🔍 Trying search: "${searchQuery}"`);
        
        const nvdUrl = `https://bliwnrikjfzcialoznur.supabase.co/functions/v1/nvd-proxy?keywordSearch=${encodeURIComponent(searchQuery)}`;
        
        const response = await fetch(nvdUrl, {
          method: 'GET',
          headers: {
            'Authorization': `Bearer ${session.access_token}`,
            'Content-Type': 'application/json',
          },
        });

        if (!response.ok) {
          console.warn(`⚠️ NVD lookup failed for "${searchQuery}": ${response.status}`);
          continue;
        }

        const nvdData = await response.json();
        vulnerabilities = nvdData.vulnerabilities || [];
        
        if (vulnerabilities.length > 0) {
          successfulQuery = searchQuery;
          console.log(`✅ Found ${vulnerabilities.length} CVEs with query: "${searchQuery}"`);
          break;
        }
        
        // Small delay between attempts
        await new Promise(resolve => setTimeout(resolve, 500));
      }

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
