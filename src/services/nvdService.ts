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
    // Get session for authorization
    const { data: { session }, error: sessionError } = await supabase.auth.getSession();
    
    if (sessionError) {
      console.error('Session error:', sessionError);
      throw new Error('Authentication error. Please try logging out and back in.');
    }
    
    if (!session?.access_token) {
      throw new Error('Not authenticated. Please log in to search vulnerabilities.');
    }

    // Build search query - combine service name and version if provided
    const searchQuery = version ? `${serviceName} ${version}` : serviceName;
    console.log('Searching NVD for:', searchQuery);

    // Call nvd-proxy edge function
    const { data, error } = await supabase.functions.invoke('nvd-proxy', {
      body: { keywordSearch: searchQuery }
    });

    if (error) {
      console.error('NVD proxy error:', error);
      throw new Error(`Search failed: ${error.message || 'Unknown error'}`);
    }

    console.log('NVD search successful:', data);
    return data as NVDResponse;
  } catch (error) {
    console.error('CVE search error:', error);
    throw error instanceof Error ? error : new Error('An unexpected error occurred');
  }
};
