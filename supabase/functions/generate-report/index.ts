
import "https://deno.land/x/xhr@0.1.0/mod.ts";
import { serve } from "https://deno.land/std@0.168.0/http/server.ts";
import { createClient } from 'https://esm.sh/@supabase/supabase-js@2';
import { jsPDF } from 'https://esm.sh/jspdf@2.5.1';

const corsHeaders = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Headers': 'authorization, x-client-info, apikey, content-type',
};

const supabase = createClient(
  Deno.env.get('SUPABASE_URL') ?? '',
  Deno.env.get('SUPABASE_SERVICE_ROLE_KEY') ?? ''
);

interface CVEData {
  cve_id: string;
  title: string;
  description: string;
  cvss_score: number | null;
}

interface Finding {
  port: number;
  service_name: string;
  service_version: string | null;
  cve_id: string | null;
}

serve(async (req) => {
  if (req.method === 'OPTIONS') {
    return new Response(null, { headers: corsHeaders });
  }

  try {
    const { scanId } = await req.json();
    
    console.log('Processing report generation for scanId:', scanId);
    
    // Get Gemini API key
    const geminiApiKey = Deno.env.get('GEMINI_API_KEY');
    
    if (!geminiApiKey) {
      console.error('Gemini API key not found');
      return new Response(JSON.stringify({ 
        error: 'Gemini API key not configured' 
      }), {
        status: 500,
        headers: { ...corsHeaders, 'Content-Type': 'application/json' },
      });
    }

    console.log('Fetching scan data for scanId:', scanId);

    // Get scan details
    const { data: scan, error: scanError } = await supabase
      .from('scans')
      .select('*')
      .eq('scan_id', scanId)
      .single();

    if (scanError) {
      console.error('Scan fetch error:', scanError);
      return new Response(JSON.stringify({ 
        error: 'Scan not found',
        details: scanError.message 
      }), {
        status: 404,
        headers: { ...corsHeaders, 'Content-Type': 'application/json' },
      });
    }

    console.log('Scan data retrieved successfully');

    // Get findings
    const { data: findings, error: findingsError } = await supabase
      .from('findings')
      .select('*')
      .eq('scan_id', scanId);

    if (findingsError) {
      console.error('Findings fetch error:', findingsError);
      return new Response(JSON.stringify({ 
        error: 'Failed to fetch findings',
        details: findingsError.message 
      }), {
        status: 500,
        headers: { ...corsHeaders, 'Content-Type': 'application/json' },
      });
    }

    console.log('Findings retrieved:', findings?.length || 0, 'findings');

    // Get CVE details for all findings with CVE IDs
    const cveIds = findings?.filter(f => f.cve_id).map(f => f.cve_id) || [];
    let cveDetails: CVEData[] = [];
    
    if (cveIds.length > 0) {
      console.log('Fetching CVE details for:', cveIds.length, 'CVEs');
      const { data: cves, error: cveError } = await supabase
        .from('cve')
        .select('*')
        .in('cve_id', cveIds);
      
      if (!cveError && cves) {
        cveDetails = cves;
        console.log('Retrieved CVE details:', cveDetails.length);
      }
    }

    // Prepare detailed findings summary with CVE information
    const findingsSummary = findings && findings.length > 0 
      ? findings.map(finding => {
          const cve = cveDetails.find(c => c.cve_id === finding.cve_id);
          let summary = `Port ${finding.port}: ${finding.service_name} ${finding.service_version || ''}`;
          
          if (cve) {
            summary += `\n  CVE: ${cve.cve_id} (CVSS Score: ${cve.cvss_score || 'N/A'})`;
            summary += `\n  Description: ${cve.description.substring(0, 200)}...`;
          }
          
          return summary;
        }).join('\n\n')
      : 'No vulnerabilities found - all scanned services appear to be secure.';

    // Generate AI report using Gemini
    const prompt = `You are a cybersecurity expert. Generate a comprehensive security scan report for target: ${scan.target}

SCAN FINDINGS:
${findingsSummary}

Please provide a detailed report with the following sections:

1. **Executive Summary**
   - Brief overview in 2-3 sentences
   - Overall security posture assessment

2. **Risk Assessment**
   - Overall risk level: Low/Medium/High/Critical
   - Risk justification based on findings

3. **Detailed Vulnerability Analysis**
   For each vulnerability found:
   - CVE ID and CVSS score
   - Clear explanation of what the vulnerability is
   - Potential impact if exploited
   - Attack scenarios

4. **Recommended Remediation Actions**
   For each vulnerability, provide:
   - Specific step-by-step fixes
   - Patch versions or configuration changes needed
   - Priority level (Critical/High/Medium/Low)
   - Implementation timeline recommendations

5. **Additional Security Recommendations**
   - General security best practices
   - Preventive measures

Use clear, professional language suitable for both technical and non-technical stakeholders.`;

    console.log('Making Gemini API request...');

    const geminiResponse = await fetch(`https://generativelanguage.googleapis.com/v1beta/models/gemini-2.0-flash:generateContent`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-goog-api-key': geminiApiKey,
      },
      body: JSON.stringify({
        contents: [{
          parts: [{ text: prompt }]
        }],
        generationConfig: {
          temperature: 0.3,
          maxOutputTokens: 4096,
        }
      }),
    });

    console.log('Gemini response status:', geminiResponse.status);

    if (!geminiResponse.ok) {
      const errorText = await geminiResponse.text();
      console.error('Gemini API error - Status:', geminiResponse.status);
      console.error('Gemini API error - Response:', errorText);
      
      return new Response(JSON.stringify({ 
        error: `Gemini API error (${geminiResponse.status})`,
        details: errorText
      }), {
        status: 500,
        headers: { ...corsHeaders, 'Content-Type': 'application/json' },
      });
    }

    const aiData = await geminiResponse.json();
    console.log('Gemini response received successfully');
    
    if (!aiData.candidates || !aiData.candidates[0] || !aiData.candidates[0].content) {
      console.error('Unexpected Gemini response structure:', aiData);
      return new Response(JSON.stringify({ 
        error: 'Unexpected response from Gemini API',
        details: 'Response structure was not as expected'
      }), {
        status: 500,
        headers: { ...corsHeaders, 'Content-Type': 'application/json' },
      });
    }
    
    const reportContent = aiData.candidates[0].content.parts[0].text;
    console.log('AI report generated successfully, length:', reportContent.length);

    // Generate PDF from report content
    console.log('Generating PDF...');
    const pdf = new jsPDF({
      format: 'a4',
      unit: 'mm',
    });

    // Add title
    pdf.setFontSize(20);
    pdf.text('Security Scan Report', 20, 20);
    
    pdf.setFontSize(12);
    pdf.text(`Target: ${scan.target}`, 20, 35);
    pdf.text(`Date: ${new Date().toLocaleString()}`, 20, 42);
    
    // Add report content
    pdf.setFontSize(10);
    const splitText = pdf.splitTextToSize(reportContent, 170);
    pdf.text(splitText, 20, 55);

    // Convert PDF to base64
    const pdfBase64 = pdf.output('datauristring').split(',')[1];
    const pdfBuffer = Uint8Array.from(atob(pdfBase64), c => c.charCodeAt(0));
    
    console.log('PDF generated successfully, size:', pdfBuffer.length);

    // Upload PDF to storage
    console.log('Uploading PDF to storage...');
    const fileName = `${scanId}/report_${Date.now()}.pdf`;
    const { error: uploadError } = await supabase.storage
      .from('reports')
      .upload(fileName, pdfBuffer, {
        contentType: 'application/pdf',
        upsert: true
      });

    if (uploadError) {
      console.error('PDF upload error:', uploadError);
      return new Response(JSON.stringify({ 
        error: 'Failed to upload PDF',
        details: uploadError.message 
      }), {
        status: 500,
        headers: { ...corsHeaders, 'Content-Type': 'application/json' },
      });
    }

    console.log('PDF uploaded successfully');

    // Get public URL
    const { data: { publicUrl } } = supabase.storage
      .from('reports')
      .getPublicUrl(fileName);

    console.log('PDF public URL:', publicUrl);

    // Store the report with PDF URL
    console.log('Storing report in database...');
    const { error: reportError } = await supabase
      .from('reports')
      .upsert({
        scan_id: scanId,
        summary: reportContent,
        fix_recommendations: extractRecommendations(reportContent),
        pdf_url: publicUrl,
        created_at: new Date().toISOString()
      }, {
        onConflict: 'scan_id'
      });

    if (reportError) {
      console.error('Report storage error:', reportError);
      return new Response(JSON.stringify({ 
        error: 'Failed to save report to database',
        details: reportError.message 
      }), {
        status: 500,
        headers: { ...corsHeaders, 'Content-Type': 'application/json' },
      });
    }

    console.log('Report saved to database successfully');

    return new Response(JSON.stringify({ 
      success: true, 
      report: reportContent,
      message: 'Report generated successfully' 
    }), {
      headers: { ...corsHeaders, 'Content-Type': 'application/json' },
    });

  } catch (error) {
    console.error('Unexpected error in generate-report function:', error);
    console.error('Error stack trace:', error instanceof Error ? error.stack : 'No stack trace available');
    return new Response(JSON.stringify({ 
      error: 'Internal server error',
      details: error instanceof Error ? error.message : 'Unknown error',
      stack: error instanceof Error ? error.stack : 'No stack trace available'
    }), {
      status: 500,
      headers: { ...corsHeaders, 'Content-Type': 'application/json' },
    });
  }
});

// Helper function to extract recommendations from AI response
function extractRecommendations(content: string): string {
  const sections = content.split('\n\n');
  const recommendationsSection = sections.find(section => 
    section.toLowerCase().includes('recommended actions') || 
    section.toLowerCase().includes('recommendations')
  );
  return recommendationsSection || content;
}
