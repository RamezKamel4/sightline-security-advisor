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
  // Get session for authorization
  const { data: { session } } = await supabase.auth.getSession();
  if (!session) {
    throw new Error('Not authenticated');
  }

  // Build search query - combine service name and version if provided
  const searchQuery = version ? `${serviceName} ${version}` : serviceName;

  // Call nvd-proxy edge function with keyword search
  const url = `https://bliwnrikjfzcialoznur.supabase.co/functions/v1/nvd-proxy?keywordSearch=${encodeURIComponent(searchQuery)}`;
  
  const response = await fetch(url, {
    method: 'GET',
    headers: {
      'Authorization': `Bearer ${session.access_token}`,
      'Content-Type': 'application/json',
    },
  });

  if (!response.ok) {
    const errorData = await response.json();
    throw new Error(errorData.error || 'Failed to search vulnerabilities');
  }

  return response.json();
};
