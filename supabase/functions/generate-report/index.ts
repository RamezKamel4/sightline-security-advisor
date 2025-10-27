
import "https://deno.land/x/xhr@0.1.0/mod.ts";
import { serve } from "https://deno.land/std@0.168.0/http/server.ts";
import { createClient } from 'https://esm.sh/@supabase/supabase-js@2';
import { PDFDocument, StandardFonts, rgb } from 'https://cdn.skypack.dev/pdf-lib@1.17.1';

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
    
    // Get app URL for CVE links (use production URL)
    const appUrl = Deno.env.get('APP_URL') ?? 'https://2f7ebd3f-a3b3-449b-94ac-f2a2c2d67068.lovableproject.com';
    
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
    console.log('Findings ports:', findings?.map(f => f.port).join(', '));

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

    // Prepare detailed findings with full CVE information
    const findingsWithCVE = findings && findings.length > 0 
      ? findings.map(finding => {
          const cve = cveDetails.find(c => c.cve_id === finding.cve_id);
          return {
            port: finding.port,
            service: finding.service_name,
            version: finding.service_version || 'unknown',
            cve_id: cve?.cve_id || null,
            cvss_score: cve?.cvss_score || null,
            cve_description: cve?.description || null
          };
        })
      : [];

    // Create a structured summary for the prompt
    const findingsSummary = findingsWithCVE.length > 0
      ? findingsWithCVE.map((f, index) => {
          let summary = `Finding ${index + 1}:\n`;
          summary += `  Port: ${f.port}\n`;
          summary += `  Service: ${f.service}\n`;
          summary += `  Version: ${f.version}\n`;
          
          if (f.cve_id && f.cvss_score) {
            summary += `  CVE ID: ${f.cve_id}\n`;
            summary += `  CVSS Score: ${f.cvss_score}\n`;
            summary += `  Technical Description: ${f.cve_description}\n`;
          } else {
            summary += `  CVE ID: No CVE found\n`;
            summary += `  CVSS Score: N/A\n`;
          }
          
          return summary;
        }).join('\n')
      : 'No vulnerabilities found - all scanned services appear to be secure.';

    // Generate AI report using Gemini with explicit instructions
    const prompt = `You are an AI security assistant generating professional vulnerability scan reports for SMBs and IT consultants.

SCAN FINDINGS:
${findingsSummary}

CRITICAL INSTRUCTIONS:
0. DO NOT include any preamble or introduction like "Okay, here's the client-ready security report..." - start DIRECTLY with the Executive Summary section
1. For EACH finding above, you MUST generate a complete vulnerability entry in the report
2. If a CVE ID and CVSS Score are provided, use them EXACTLY as shown - do NOT write "N/A" or "Configuration Issue"
3. If NO CVE is found for a finding, then you may write "N/A" for CVE ID and provide a risk assessment based on the service/version
4. For EVERY vulnerability (with or without CVE), you MUST provide:
   - A clear business impact explanation in plain language
   - Immediate mitigation steps
   - Permanent fix recommendations with specific version numbers when available
   - Compliance mapping to relevant standards

Generate a client-ready security report with the following structure:

## 1. EXECUTIVE SUMMARY (One Page)
- Overall risk level: Critical/High/Medium/Low (use CVSS scores to determine: 9.0-10.0 = Critical, 7.0-8.9 = High, 4.0-6.9 = Medium, 0.1-3.9 = Low)
- Top 2-3 most urgent vulnerabilities explained in plain, non-technical language
- Clear recommendations split into:
  * IMMEDIATE ACTIONS: Quick mitigation steps to reduce risk now
  * PERMANENT FIXES: Long-term patches or upgrades needed

## 2. VULNERABILITY DETAILS (For Each Finding)
You MUST create an entry for EVERY finding listed above. 

For each vulnerability, format it as follows:

### **Vulnerability [NUMBER]**

- **Port/Service/Version**: [Port number] / [Service name] / [Version or "unknown"]
- **CVE ID & CVSS Score**: [Use EXACT CVE ID and Score if provided above. If CVE ID exists, write just the CVE ID (e.g., "CVE-2021-44228") followed by " - CVSS Score: X.X". If not provided, write "N/A (No CVE match found)"]
- **Business Impact Explanation**: Write 2-3 sentences in plain, non-technical language explaining what an attacker could do and why this matters to the business. Focus on real-world consequences like data theft, service disruption, or financial loss.
- **IMMEDIATE FIX**: Provide 1-2 actionable steps that can be taken RIGHT NOW to reduce risk (e.g., "Block external access to port X", "Enable firewall rules", "Restrict access to known IPs")
- **PERMANENT FIX**: Provide specific patch/upgrade instructions with exact version numbers when available (e.g., "Update Apache from 2.4.49 to 2.4.51 or later"). If no specific version is known, provide general hardening advice.
- **Compliance Mapping**: List relevant standards violated (e.g., PCI DSS Req. 6.2, ISO-27001 A.12.6.1, NIST CSF PR.IP-12)

Add a blank line between each vulnerability for readability.

IMPORTANT: Even if a finding has no CVE match, you MUST still provide business impact analysis, fixes, and compliance mapping based on the service and version information.

## 3. RISK PRIORITIZATION
Group all findings by severity:
- **CRITICAL**: Immediate attention required
- **HIGH**: Address within 1 week
- **MEDIUM**: Address within 1 month
- **LOW**: Address when convenient

Order vulnerabilities by severity within each group.

## 4. SCAN METHODOLOGY & LIMITATIONS
Provide a brief technical explanation covering:
- Why some service banners appeared as "unknown" (Nmap version detection limitations, firewall filtering, IPS restrictions, or services configured to suppress banner information)
- Why only certain ports were scanned (explain the scan profile used, e.g., web-apps profile focusing on web-related services, deliberately excluding system-level ports like SMB or NetBIOS)
- How environmental restrictions and deliberate scan scope affected version detection capabilities

## 5. TECHNICAL SUMMARY
Include technical details:
- Open ports discovered
- Service banners and versions detected
DO NOT include any "Raw Tool Outputs" section

## STYLE REQUIREMENTS:
- Write in professional, client-ready language
- Executive Summary and Vulnerability Details must avoid technical jargon
- Focus on business risk and impact, not just technical details
- Summaries must be short, impactful, and actionable
- Technical Appendix can include detailed technical information
- Use bullet points and clear section headers for easy PDF conversion

Generate the complete report now.`;

    console.log('Making Gemini API request with retry logic...');

    let geminiResponse;
    let lastError;
    const maxRetries = 3;
    
    for (let attempt = 1; attempt <= maxRetries; attempt++) {
      try {
        console.log(`Attempt ${attempt}/${maxRetries} to call Gemini API...`);
        
        geminiResponse = await fetch(`https://generativelanguage.googleapis.com/v1beta/models/gemini-2.0-flash:generateContent`, {
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
              maxOutputTokens: 16384,
            }
          }),
        });

        console.log('Gemini response status:', geminiResponse.status);

        // Success - break out of retry loop
        if (geminiResponse.ok) {
          break;
        }

        // Handle retryable errors (503 Service Unavailable, 429 Rate Limit)
        if (geminiResponse.status === 503 || geminiResponse.status === 429) {
          const errorText = await geminiResponse.text();
          lastError = errorText;
          console.error(`Gemini API error (attempt ${attempt}/${maxRetries}) - Status:`, geminiResponse.status);
          console.error('Error response:', errorText);
          
          // Don't retry on last attempt
          if (attempt < maxRetries) {
            const delayMs = Math.pow(2, attempt - 1) * 1000; // Exponential backoff: 1s, 2s, 4s
            console.log(`Retrying after ${delayMs}ms...`);
            await new Promise(resolve => setTimeout(resolve, delayMs));
            continue;
          }
        } else {
          // Non-retryable error
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
      } catch (fetchError) {
        console.error(`Fetch error on attempt ${attempt}:`, fetchError);
        lastError = fetchError instanceof Error ? fetchError.message : 'Network error';
        
        if (attempt < maxRetries) {
          const delayMs = Math.pow(2, attempt - 1) * 1000;
          console.log(`Retrying after ${delayMs}ms...`);
          await new Promise(resolve => setTimeout(resolve, delayMs));
        }
      }
    }

    // If we exhausted all retries
    if (!geminiResponse || !geminiResponse.ok) {
      console.error('Failed after all retry attempts');
      return new Response(JSON.stringify({ 
        error: 'Gemini API is temporarily unavailable',
        details: 'The AI service is overloaded. Please try again in a few minutes.',
        technicalDetails: lastError
      }), {
        status: 503,
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
    
    let reportContent = aiData.candidates[0].content.parts[0].text;
    console.log('AI report generated successfully, length:', reportContent.length);
    
    // Remove any preamble text that starts with common phrases
    const preamblePatterns = [
      /^Okay,\s+here'?s?\s+the\s+client-ready\s+security\s+report[^\n]*\n+/i,
      /^Here'?s?\s+the\s+client-ready\s+security\s+report[^\n]*\n+/i,
      /^Here'?s?\s+a\s+client-ready\s+security\s+report[^\n]*\n+/i,
    ];
    
    for (const pattern of preamblePatterns) {
      reportContent = reportContent.replace(pattern, '');
    }
    
    // Format scan date
    const scanDate = new Date(scan.start_time || scan.created_at).toLocaleDateString('en-US', {
      year: 'numeric',
      month: 'long',
      day: 'numeric'
    });
    
    // Prepend scan metadata to report
    const metadata = `# Security Scan Report

**Scan Date:** ${scanDate}
**Target:** ${scan.target}
**Scan Profile:** ${scan.profile || 'Default'}

---

`;
    
    reportContent = metadata + reportContent;

    // Generate PDF
    console.log('Generating PDF...');
    const pdfDoc = await PDFDocument.create();
    const font = await pdfDoc.embedFont(StandardFonts.Helvetica);
    const boldFont = await pdfDoc.embedFont(StandardFonts.HelveticaBold);
    
    const fontSize = 11;
    const margin = 50;
    const lineHeight = fontSize * 1.5;
    let currentPage = pdfDoc.addPage();
    let { width, height } = currentPage.getSize();
    let yPosition = height - margin;
    
    // PDF header is now part of the report content, so we skip adding a separate title
    // Just start with the report content directly
    
    // Split report content into lines and add to PDF
    const lines = reportContent.split('\n');
    const cveRegex = /CVE-\d{4}-\d{4,7}/g;
    
    for (const line of lines) {
      // Check if we need a new page
      if (yPosition < margin + lineHeight) {
        currentPage = pdfDoc.addPage();
        yPosition = height - margin;
      }
      
      // Determine if line is a header (starts with # or **)
      const isHeader = line.trim().startsWith('#') || line.trim().startsWith('**');
      const cleanLine = line.replace(/^#+\s*/, '').replace(/\*\*/g, '');
      
      // Word wrap long lines
      const maxWidth = width - (2 * margin);
      const words = cleanLine.split(' ');
      let currentLine = '';
      
      for (const word of words) {
        const testLine = currentLine + (currentLine ? ' ' : '') + word;
        const textWidth = (isHeader ? boldFont : font).widthOfTextAtSize(testLine, fontSize);
        
        if (textWidth > maxWidth && currentLine) {
          // Draw current line with CVE highlighting
          drawLineWithCVEHighlight(currentPage, currentLine, margin, yPosition, fontSize, isHeader ? boldFont : font);
          yPosition -= lineHeight;
          currentLine = word;
          
          // Check for new page
          if (yPosition < margin + lineHeight) {
            currentPage = pdfDoc.addPage();
            yPosition = height - margin;
          }
        } else {
          currentLine = testLine;
        }
      }
      
      // Draw remaining text with CVE highlighting
      if (currentLine) {
        drawLineWithCVEHighlight(currentPage, currentLine, margin, yPosition, fontSize, isHeader ? boldFont : font);
        yPosition -= lineHeight;
      }
      
      // Add extra spacing after headers
      if (isHeader) {
        yPosition -= lineHeight * 0.5;
      }
    }
    
    // Helper function to draw text with CVE IDs in blue
    function drawLineWithCVEHighlight(page: any, text: string, x: number, y: number, size: number, textFont: any) {
      const cveMatches = Array.from(text.matchAll(cveRegex));
      
      if (cveMatches.length === 0) {
        // No CVE IDs, draw normally
        page.drawText(text, {
          x,
          y,
          size,
          font: textFont,
          color: rgb(0, 0, 0),
        });
        return;
      }
      
      let currentX = x;
      let lastIndex = 0;
      
      for (const match of cveMatches) {
        const cveId = match[0];
        const beforeText = text.substring(lastIndex, match.index);
        
        // Draw text before CVE
        if (beforeText) {
          page.drawText(beforeText, {
            x: currentX,
            y,
            size,
            font: textFont,
            color: rgb(0, 0, 0),
          });
          currentX += textFont.widthOfTextAtSize(beforeText, size);
        }
        
        // Draw CVE ID in blue
        page.drawText(cveId, {
          x: currentX,
          y,
          size,
          font: textFont,
          color: rgb(0, 0, 1), // Blue color
        });
        
        currentX += textFont.widthOfTextAtSize(cveId, size);
        lastIndex = match.index + cveId.length;
      }
      
      // Draw remaining text after last CVE
      const remainingText = text.substring(lastIndex);
      if (remainingText) {
        page.drawText(remainingText, {
          x: currentX,
          y,
          size,
          font: textFont,
          color: rgb(0, 0, 0),
        });
      }
    }
    
    const pdfBytes = await pdfDoc.save();
    console.log('PDF generated, size:', pdfBytes.length, 'bytes');
    
    // Upload PDF to storage
    console.log('Uploading PDF to storage...');
    const fileName = `${scanId}/report-${Date.now()}.pdf`;
    const { error: uploadError } = await supabase.storage
      .from('reports')
      .upload(fileName, pdfBytes, {
        contentType: 'application/pdf',
        upsert: true
      });
    
    if (uploadError) {
      console.error('PDF upload error:', uploadError);
      // Continue anyway - we'll save the report without the PDF
    }
    
    // Get public URL for the PDF
    const { data: urlData } = supabase.storage
      .from('reports')
      .getPublicUrl(fileName);
    
    const pdfUrl = uploadError ? null : urlData.publicUrl;
    console.log('PDF URL:', pdfUrl);

    // Store the report
    console.log('Storing report in database...');
    const { error: reportError } = await supabase
      .from('reports')
      .upsert({
        scan_id: scanId,
        summary: reportContent,
        fix_recommendations: extractRecommendations(reportContent),
        pdf_url: pdfUrl,
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
      pdfUrl: pdfUrl,
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
