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
  const { data, error } = await supabase.functions.invoke('nvd-proxy', {
    body: {},
    method: 'GET',
    headers: {
      'Content-Type': 'application/json',
    },
  });

  if (error) {
    throw new Error(`Failed to lookup CVE: ${error.message}`);
  }

  // The nvd-proxy function is called via GET with query params
  // We need to construct the URL properly
  const url = `https://bliwnrikjfzcialoznur.supabase.co/functions/v1/nvd-proxy?cveId=${encodeURIComponent(cveId)}`;
  
  const response = await fetch(url, {
    method: 'GET',
    headers: {
      'Authorization': `Bearer ${(await supabase.auth.getSession()).data.session?.access_token}`,
      'Content-Type': 'application/json',
    },
  });

  if (!response.ok) {
    const errorData = await response.json();
    throw new Error(errorData.error || 'Failed to lookup CVE');
  }

  return response.json();
};
