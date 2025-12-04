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

/**
 * Compare semantic versions (e.g., "2.4.50" vs "2.4.26")
 * Returns: -1 if v1 < v2, 0 if equal, 1 if v1 > v2
 */
function compareVersions(v1: string, v2: string): number {
  const parts1 = v1.split('.').map(p => parseInt(p) || 0);
  const parts2 = v2.split('.').map(p => parseInt(p) || 0);
  
  const maxLength = Math.max(parts1.length, parts2.length);
  
  for (let i = 0; i < maxLength; i++) {
    const p1 = parts1[i] || 0;
    const p2 = parts2[i] || 0;
    
    if (p1 < p2) return -1;
    if (p1 > p2) return 1;
  }
  
  return 0;
}

/**
 * Check if a version falls within a vulnerable range defined by CPE match criteria
 */
function isVersionVulnerable(
  version: string,
  versionStartIncluding?: string,
  versionEndIncluding?: string,
  versionStartExcluding?: string,
  versionEndExcluding?: string
): boolean {
  // If no version constraints specified, consider it vulnerable (generic CPE match)
  if (!versionStartIncluding && !versionEndIncluding && !versionStartExcluding && !versionEndExcluding) {
    return true;
  }
  
  // Check start range (inclusive)
  if (versionStartIncluding && compareVersions(version, versionStartIncluding) < 0) {
    return false;
  }
  
  // Check start range (exclusive)
  if (versionStartExcluding && compareVersions(version, versionStartExcluding) <= 0) {
    return false;
  }
  
  // Check end range (inclusive)
  if (versionEndIncluding && compareVersions(version, versionEndIncluding) > 0) {
    return false;
  }
  
  // Check end range (exclusive)
  if (versionEndExcluding && compareVersions(version, versionEndExcluding) >= 0) {
    return false;
  }
  
  return true;
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
      // Smart extraction of product name and version from keywordSearch
      // Handle formats like "Apache httpd 2.4.7", "nginx 1.18.0", "OpenSSH 8.2p1"
      let serviceName = '';
      let version = '';
      
      // Product name patterns (handles multi-word product names)
      const productPatterns = [
        /^(Apache\s+httpd)\s+(\d+[\d.p]*)/i,
        /^(Apache\s+Tomcat)\s+(\d+[\d.]*)/i,
        /^(Microsoft\s+IIS)\s+(\d+[\d.]*)/i,
        /^(Eclipse\s+Jetty)\s+(\d+[\d.]*)/i,
        /^(nginx)\s+(\d+[\d.]*)/i,
        /^(OpenSSH)[_\s]+(\d+[\d.p]*)/i,
        /^(lighttpd)\s+(\d+[\d.]*)/i,
        /^(\w+)\s+(\d+[\d.]*)/i,  // Generic fallback: word + version
      ];
      
      if (keywordSearch) {
        let matched = false;
        for (const pattern of productPatterns) {
          const match = keywordSearch.match(pattern);
          if (match) {
            serviceName = match[1].toLowerCase().replace(/\s+/g, '_');
            version = match[2].toLowerCase();
            console.log(`📦 Extracted product: "${serviceName}", version: "${version}" from "${keywordSearch}"`);
            matched = true;
            break;
          }
        }
        
        if (!matched) {
          // Fallback to simple split
          const searchParts = keywordSearch.split(' ');
          serviceName = searchParts[0]?.toLowerCase() || '';
          version = searchParts.slice(1).join(' ').toLowerCase();
        }
      }
      
      // Normalize product names for CPE matching
      const cpeProductMap: Record<string, string[]> = {
        'apache_httpd': ['apache', 'httpd', 'http_server'],
        'apache_tomcat': ['tomcat'],
        'microsoft_iis': ['iis', 'internet_information_services'],
        'eclipse_jetty': ['jetty'],
        'openssh': ['openssh'],
      };
      
      // Get all possible CPE product names for matching
      const productVariants = cpeProductMap[serviceName] || [serviceName];
      
      // Filter and score vulnerabilities with proper version range validation
      filteredVulnerabilities = filteredVulnerabilities.map((vuln: any) => {
        const cve = vuln.cve;
        const publishedDate = cve.published || '';
        const year = publishedDate ? parseInt(publishedDate.substring(0, 4)) : 2025;
        
        // Calculate confidence score and validate version ranges
        let confidence = 'low';
        let hasProductMatch = false;
        let hasVersionMatch = false;
        let isActuallyVulnerable = false;
        
        const configurations = cve.configurations || [];
        for (const config of configurations) {
          for (const node of config.nodes || []) {
            for (const cpeMatch of node.cpeMatch || []) {
              const cpeCriteria = (cpeMatch.criteria || '').toLowerCase();
              
              // Check all product name variants for matching
              const matchesProduct = productVariants.some(variant => 
                cpeCriteria.includes(`:${variant}:`)
              );
              
              if (serviceName && matchesProduct) {
                hasProductMatch = true;
                
                if (version) {
                  // Check if version is actually vulnerable using range validation
                  const versionStartIncluding = cpeMatch.versionStartIncluding;
                  const versionEndIncluding = cpeMatch.versionEndIncluding;
                  const versionStartExcluding = cpeMatch.versionStartExcluding;
                  const versionEndExcluding = cpeMatch.versionEndExcluding;
                  
                  const vulnerable = isVersionVulnerable(
                    version,
                    versionStartIncluding,
                    versionEndIncluding,
                    versionStartExcluding,
                    versionEndExcluding
                  );
                  
                  if (vulnerable) {
                    hasVersionMatch = true;
                    isActuallyVulnerable = true;
                    confidence = 'high';
                    console.log(`✅ Version ${version} IS vulnerable to ${cve.id} (range validated)`);
                    break;
                  } else {
                    console.log(`❌ Version ${version} NOT vulnerable to ${cve.id} (outside range)`);
                  }
                  
                  // Also check exact version match in CPE
                  if (cpeCriteria.includes(`:${serviceName}:${version}`)) {
                    hasVersionMatch = true;
                    isActuallyVulnerable = true;
                    confidence = 'high';
                    console.log(`✅ Version ${version} IS vulnerable to ${cve.id} (exact CPE match)`);
                    break;
                  }
                }
              }
            }
            if (hasVersionMatch && isActuallyVulnerable) break;
          }
          if (hasVersionMatch && isActuallyVulnerable) break;
        }
        
        if (hasProductMatch && !hasVersionMatch) {
          confidence = 'medium';
        }
        
        return { 
          ...vuln, 
          _confidence: confidence, 
          _year: year,
          _isActuallyVulnerable: isActuallyVulnerable
        };
      });
      
      // Filter out CVEs that don't match version ranges and old low-confidence CVEs
      filteredVulnerabilities = filteredVulnerabilities.filter((vuln: any) => {
        // For high confidence matches, only keep if version is actually vulnerable
        if (vuln._confidence === 'high') {
          return vuln._isActuallyVulnerable === true;
        }
        // For lower confidence, filter by year
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
