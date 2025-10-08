
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
    const prompt = `You are an AI security assistant generating professional vulnerability scan reports for SMBs and IT consultants.

TARGET: ${scan.target}

SCAN FINDINGS:
${findingsSummary}

Generate a client-ready security report with the following structure:

## 1. EXECUTIVE SUMMARY (One Page)
- Overall risk level: Critical/High/Medium/Low
- Top 2-3 most urgent vulnerabilities explained in plain, non-technical language
- Clear recommendations split into:
  * IMMEDIATE ACTIONS: Quick mitigation steps to reduce risk now
  * PERMANENT FIXES: Long-term patches or upgrades needed

## 2. VULNERABILITY DETAILS (For Each Finding)
For each vulnerability, provide:
- **Port/Service/Version**: What was found
- **CVE ID & CVSS Score**: Severity rating
- **Business Impact Explanation**: Describe in simple terms what hackers could do (e.g., "Hackers can steal customer data" or "Systems could be taken offline")
- **IMMEDIATE FIX**: Short-term mitigation step to reduce risk quickly
- **PERMANENT FIX**: Proper patch, upgrade, or configuration change with version numbers
- **Compliance Mapping**: Which standards are violated (e.g., PCI DSS Req. 6.2, ISO-27001 A.12.6.1, NIST CSF PR.IP-12)

## 3. RISK PRIORITIZATION
Group all findings by severity:
- **CRITICAL**: Immediate attention required
- **HIGH**: Address within 1 week
- **MEDIUM**: Address within 1 month
- **LOW**: Address when convenient

Order vulnerabilities by severity within each group.

## 4. TECHNICAL APPENDIX
Include raw technical details:
- Open ports discovered
- Service banners and versions detected
- Nmap commands used for scanning
- Raw tool outputs (keep this separate from executive summary)

## STYLE REQUIREMENTS:
- Write in professional, client-ready language
- Executive Summary and Vulnerability Details must avoid technical jargon
- Focus on business risk and impact, not just technical details
- Summaries must be short, impactful, and actionable
- Technical Appendix can include detailed technical information
- Use bullet points and clear section headers for easy PDF conversion

Generate the complete report now.`;

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
    
    // Add title
    currentPage.drawText('Security Scan Report', {
      x: margin,
      y: yPosition,
      size: 20,
      font: boldFont,
      color: rgb(0, 0, 0),
    });
    yPosition -= 40;
    
    // Add scan details
    currentPage.drawText(`Target: ${scan.target}`, {
      x: margin,
      y: yPosition,
      size: fontSize,
      font: font,
      color: rgb(0.2, 0.2, 0.2),
    });
    yPosition -= lineHeight * 2;
    
    // Split report content into lines and add to PDF
    const lines = reportContent.split('\n');
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
          // Draw current line
          currentPage.drawText(currentLine, {
            x: margin,
            y: yPosition,
            size: fontSize,
            font: isHeader ? boldFont : font,
            color: rgb(0, 0, 0),
          });
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
      
      // Draw remaining text
      if (currentLine) {
        currentPage.drawText(currentLine, {
          x: margin,
          y: yPosition,
          size: fontSize,
          font: isHeader ? boldFont : font,
          color: rgb(0, 0, 0),
        });
        yPosition -= lineHeight;
      }
      
      // Add extra spacing after headers
      if (isHeader) {
        yPosition -= lineHeight * 0.5;
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
