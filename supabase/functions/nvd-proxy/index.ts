import "https://deno.land/x/xhr@0.1.0/mod.ts";
import { serve } from "https://deno.land/std@0.168.0/http/server.ts";

const corsHeaders = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Headers': 'authorization, x-client-info, apikey, content-type',
};

const NVD_BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0";
const MAX_RETRIES = 3;
const RETRY_DELAY_MS = 3000;

async function sleep(ms: number) {
  return new Promise(resolve => setTimeout(resolve, ms));
}

async function fetchFromNVD(url: string, apiKey: string, attempt = 1): Promise<Response> {
  console.log(`Fetching from NVD (attempt ${attempt}/${MAX_RETRIES}): ${url}`);
  
  const response = await fetch(url, {
    headers: {
      'apiKey': apiKey,
      'User-Agent': 'VulnScanAI/1.0',
      'Accept': 'application/json',
    },
  });

  if (response.status === 429 && attempt < MAX_RETRIES) {
    console.log(`Rate limited (429). Waiting ${RETRY_DELAY_MS}ms before retry...`);
    await sleep(RETRY_DELAY_MS);
    return fetchFromNVD(url, apiKey, attempt + 1);
  }

  return response;
}

serve(async (req) => {
  // Handle CORS preflight requests
  if (req.method === 'OPTIONS') {
    return new Response(null, { headers: corsHeaders });
  }

  try {
    const apiKey = Deno.env.get('NVD CVE Database');
    if (!apiKey) {
      console.error('NVD CVE Database secret not configured');
      return new Response(
        JSON.stringify({ error: 'NVD API key not configured' }),
        { status: 500, headers: { ...corsHeaders, 'Content-Type': 'application/json' } }
      );
    }

    // Parse both query parameters and request body
    const url = new URL(req.url);
    let cveId = url.searchParams.get('cveId');
    let cpeName = url.searchParams.get('cpeName');
    let keywordSearch = url.searchParams.get('keywordSearch');

    // If no query params, try to parse request body
    if (!cveId && !cpeName && !keywordSearch && req.method === 'POST') {
      try {
        const body = await req.json();
        cveId = body.cveId;
        cpeName = body.cpeName;
        keywordSearch = body.keywordSearch;
      } catch (e) {
        console.error('Failed to parse request body:', e);
      }
    }

    if (!cveId && !cpeName && !keywordSearch) {
      return new Response(
        JSON.stringify({ error: 'Either cveId, cpeName, or keywordSearch is required (query parameter or request body)' }),
        { status: 400, headers: { ...corsHeaders, 'Content-Type': 'application/json' } }
      );
    }

    // Build NVD API URL
    const nvdUrl = new URL(NVD_BASE_URL);
    if (cveId) {
      nvdUrl.searchParams.set('cveId', cveId);
    }
    if (cpeName) {
      nvdUrl.searchParams.set('cpeName', cpeName);
    }
    if (keywordSearch) {
      nvdUrl.searchParams.set('keywordSearch', keywordSearch);
    }

    console.log(`Proxying request to NVD API: ${nvdUrl.toString()}`);

    // Call NVD API with retry logic
    const nvdResponse = await fetchFromNVD(nvdUrl.toString(), apiKey);

    if (!nvdResponse.ok) {
      const errorText = await nvdResponse.text();
      console.error(`NVD API error (${nvdResponse.status}): ${errorText}`);
      return new Response(
        JSON.stringify({ 
          error: `NVD API returned status ${nvdResponse.status}`,
          details: errorText 
        }),
        { 
          status: nvdResponse.status, 
          headers: { ...corsHeaders, 'Content-Type': 'application/json' } 
        }
      );
    }

    const data = await nvdResponse.json();
    console.log(`Successfully fetched data from NVD. Vulnerabilities found: ${data.vulnerabilities?.length || 0}`);

    // Apply smart filtering to reduce irrelevant results
    let filteredVulnerabilities = data.vulnerabilities || [];
    
    // Skip filtering if keyword search contains "unknown" version
    if (keywordSearch && keywordSearch.toLowerCase().includes(' unknown')) {
      console.log('⚠️ Skipping results - query contains "unknown" version');
      filteredVulnerabilities = [];
    } else if (filteredVulnerabilities.length > 0) {
      // Extract service name and version from keywordSearch
      const searchParts = keywordSearch?.split(' ') || [];
      const serviceName = searchParts[0]?.toLowerCase();
      const version = searchParts.slice(1).join(' ').toLowerCase();
      
      // Filter and score vulnerabilities
      filteredVulnerabilities = filteredVulnerabilities.map((vuln: any) => {
        const cve = vuln.cve;
        const publishedDate = cve.published || '';
        const year = publishedDate ? parseInt(publishedDate.substring(0, 4)) : 2025;
        
        // Calculate confidence score
        let confidence = 'low';
        let hasProductMatch = false;
        let hasVersionMatch = false;
        
        const configurations = cve.configurations || [];
        for (const config of configurations) {
          for (const node of config.nodes || []) {
            for (const cpeMatch of node.cpeMatch || []) {
              const cpeCriteria = (cpeMatch.criteria || '').toLowerCase();
              
              // Precise product matching
              if (serviceName && cpeCriteria.includes(`:${serviceName}:`)) {
                hasProductMatch = true;
                
                // Exact version matching
                if (version && cpeCriteria.includes(`:${serviceName}:${version}`)) {
                  hasVersionMatch = true;
                  confidence = 'high';
                  break;
                }
                
                // Version range matching
                const versionStart = cpeMatch.versionStartIncluding || '';
                const versionEnd = cpeMatch.versionEndIncluding || '';
                if (version && versionStart && versionEnd) {
                  if (versionStart <= version && version <= versionEnd) {
                    hasVersionMatch = true;
                    confidence = 'high';
                    break;
                  }
                }
              }
            }
            if (hasVersionMatch) break;
          }
          if (hasVersionMatch) break;
        }
        
        if (hasProductMatch && !hasVersionMatch) {
          confidence = 'medium';
        }
        
        return { ...vuln, _confidence: confidence, _year: year };
      });
      
      // Filter out old low-confidence CVEs
      filteredVulnerabilities = filteredVulnerabilities.filter((vuln: any) => {
        if (vuln._confidence === 'high') return true;
        return vuln._year >= 2010;
      });
      
      // Sort by confidence and CVSS score
      filteredVulnerabilities.sort((a: any, b: any) => {
        const confidenceScore = { high: 3, medium: 2, low: 1 };
        const aConfScore = confidenceScore[a._confidence as keyof typeof confidenceScore] || 0;
        const bConfScore = confidenceScore[b._confidence as keyof typeof confidenceScore] || 0;
        
        if (aConfScore !== bConfScore) {
          return bConfScore - aConfScore;
        }
        
        const aCvss = a.cve?.metrics?.cvssMetricV31?.[0]?.cvssData?.baseScore ||
                      a.cve?.metrics?.cvssMetricV30?.[0]?.cvssData?.baseScore ||
                      a.cve?.metrics?.cvssMetricV2?.[0]?.cvssData?.baseScore || 0;
        const bCvss = b.cve?.metrics?.cvssMetricV31?.[0]?.cvssData?.baseScore ||
                      b.cve?.metrics?.cvssMetricV30?.[0]?.cvssData?.baseScore ||
                      b.cve?.metrics?.cvssMetricV2?.[0]?.cvssData?.baseScore || 0;
        
        return bCvss - aCvss;
      });
      
      console.log(`✅ Filtered to ${filteredVulnerabilities.length} relevant CVEs`);
    }

    return new Response(
      JSON.stringify({ ...data, vulnerabilities: filteredVulnerabilities }),
      { 
        status: 200, 
        headers: { ...corsHeaders, 'Content-Type': 'application/json' } 
      }
    );

  } catch (error) {
    console.error('Error in nvd-proxy function:', error);
    return new Response(
      JSON.stringify({ 
        error: 'Internal server error',
        message: error.message 
      }),
      { 
        status: 500, 
        headers: { ...corsHeaders, 'Content-Type': 'application/json' } 
      }
    );
  }
});
