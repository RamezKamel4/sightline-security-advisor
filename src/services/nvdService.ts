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

export const lookupCVE = async (cveId: string): Promise<NVDResponse> => {
  // Get session for authorization
  const { data: { session } } = await supabase.auth.getSession();
  if (!session) {
    throw new Error('Not authenticated');
  }

  // Call nvd-proxy edge function with query parameters
  const url = `https://bliwnrikjfzcialoznur.supabase.co/functions/v1/nvd-proxy?cveId=${encodeURIComponent(cveId)}`;
  
  const response = await fetch(url, {
    method: 'GET',
    headers: {
      'Authorization': `Bearer ${session.access_token}`,
      'Content-Type': 'application/json',
    },
  });

  if (!response.ok) {
    const errorData = await response.json();
    throw new Error(errorData.error || 'Failed to lookup CVE');
  }

  return response.json();
};
