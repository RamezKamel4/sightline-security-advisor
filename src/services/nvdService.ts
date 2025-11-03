import { supabase } from "@/integrations/supabase/client";

export interface NVDResponse {
  vulnerabilities?: Array<{
    cve: {
      id: string;
      descriptions: Array<{
        lang: string;
        value: string;
      }>;
      metrics?: {
        cvssMetricV31?: Array<{
          cvssData: {
            baseScore: number;
            baseSeverity: string;
          };
        }>;
      };
      published?: string;
      lastModified?: string;
    };
  }>;
  resultsPerPage?: number;
  startIndex?: number;
  totalResults?: number;
}

export const searchByServiceName = async (serviceName: string, version?: string): Promise<NVDResponse> => {
  try {
    console.log('🔍 Starting CVE search for:', serviceName, version || '(no version)');
    
    // Get session for authorization
    const { data: { session }, error: sessionError } = await supabase.auth.getSession();
    
    if (sessionError) {
      console.error('❌ Session error:', sessionError);
      throw new Error('Authentication error. Please try logging out and back in.');
    }
    
    if (!session?.access_token) {
      console.error('❌ No session token found');
      throw new Error('Not authenticated. Please log in to search vulnerabilities.');
    }

    console.log('✅ Session valid, user authenticated');

    // Build search query - combine service name and version if provided
    const searchQuery = version ? `${serviceName} ${version}` : serviceName;
    console.log('📡 Calling nvd-proxy edge function with query:', searchQuery);

    // Call nvd-proxy edge function
    const { data, error } = await supabase.functions.invoke('nvd-proxy', {
      body: { keywordSearch: searchQuery }
    });

    if (error) {
      console.error('❌ Edge function error:', error);
      throw new Error(`Search failed: ${error.message || 'Unknown error'}`);
    }

    if (!data) {
      console.error('❌ No data returned from edge function');
      throw new Error('No response from vulnerability database');
    }

    console.log('✅ NVD search successful, found:', data.totalResults || 0, 'results');
    return data as NVDResponse;
  } catch (error) {
    console.error('💥 CVE search error:', error);
    throw error instanceof Error ? error : new Error('An unexpected error occurred');
  }
};

export const searchByCveId = async (cveId: string): Promise<NVDResponse> => {
  try {
    console.log('🔍 Starting CVE ID search for:', cveId);
    
    // Normalize CVE ID by replacing Unicode dashes with standard ASCII hyphens
    // This handles copy-paste from formatted documents that use special dash characters
    const normalizedCveId = cveId
      .trim()
      .replace(/[\u2010-\u2015\u2212\uFE58\uFE63\uFF0D]/g, '-'); // Replace various Unicode dashes
    
    console.log('📝 Normalized CVE ID:', normalizedCveId);
    
    // Get session for authorization
    const { data: { session }, error: sessionError } = await supabase.auth.getSession();
    
    if (sessionError) {
      console.error('❌ Session error:', sessionError);
      throw new Error('Authentication error. Please try logging out and back in.');
    }
    
    if (!session?.access_token) {
      console.error('❌ No session token found');
      throw new Error('Not authenticated. Please log in to search vulnerabilities.');
    }

    console.log('✅ Session valid, user authenticated');
    console.log('📡 Calling nvd-proxy edge function with CVE ID:', normalizedCveId);

    // Call nvd-proxy edge function with cveId parameter
    const { data, error } = await supabase.functions.invoke('nvd-proxy', {
      body: { cveId: normalizedCveId }
    });

    if (error) {
      console.error('❌ Edge function error:', error);
      throw new Error(`Search failed: ${error.message || 'Unknown error'}`);
    }

    if (!data) {
      console.error('❌ No data returned from edge function');
      throw new Error('No response from vulnerability database');
    }

    console.log('✅ CVE ID search successful, found:', data.totalResults || 0, 'results');
    return data as NVDResponse;
  } catch (error) {
    console.error('💥 CVE ID search error:', error);
    throw error instanceof Error ? error : new Error('An unexpected error occurred');
  }
};
