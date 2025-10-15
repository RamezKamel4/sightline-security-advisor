import "https://deno.land/x/xhr@0.1.0/mod.ts";
import { serve } from "https://deno.land/std@0.168.0/http/server.ts";

const ALLOWED_ORIGINS = [
  'https://2f7ebd3f-a3b3-449b-94ac-f2a2c2d67068.lovableproject.com',
  'http://localhost:5173',
  'http://localhost:3000'
];

const getCorsHeaders = (origin: string | null) => {
  const allowedOrigin = origin && ALLOWED_ORIGINS.includes(origin) ? origin : ALLOWED_ORIGINS[0];
  return {
    'Access-Control-Allow-Origin': allowedOrigin,
    'Access-Control-Allow-Headers': 'authorization, x-client-info, apikey, content-type',
  };
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
  const corsHeaders = getCorsHeaders(req.headers.get('origin'));
  
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

    return new Response(
      JSON.stringify(data),
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
