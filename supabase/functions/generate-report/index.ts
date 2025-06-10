
import "https://deno.land/x/xhr@0.1.0/mod.ts";
import { serve } from "https://deno.land/std@0.168.0/http/server.ts";
import { createClient } from 'https://esm.sh/@supabase/supabase-js@2';

const corsHeaders = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Headers': 'authorization, x-client-info, apikey, content-type',
};

const supabase = createClient(
  Deno.env.get('SUPABASE_URL') ?? '',
  Deno.env.get('SUPABASE_SERVICE_ROLE_KEY') ?? ''
);

serve(async (req) => {
  if (req.method === 'OPTIONS') {
    return new Response(null, { headers: corsHeaders });
  }

  try {
    const { scanId } = await req.json();
    
    console.log('Processing report generation for scanId:', scanId);
    
    // Get OpenAI API key - try multiple possible names
    const openAIApiKey = Deno.env.get('OPENAI_API_KEY') || 
                         Deno.env.get('OPENAI_API_KEY (GPT-4)') ||
                         Deno.env.get('OPENAI_KEY');

    console.log('Available environment variables:', Object.keys(Deno.env.toObject()));
    console.log('OpenAI API key found:', !!openAIApiKey);
    
    if (openAIApiKey) {
      console.log('OpenAI API key starts with:', openAIApiKey.substring(0, 10) + '...');
      console.log('OpenAI API key length:', openAIApiKey.length);
    }

    if (!openAIApiKey) {
      console.error('OpenAI API key not found in environment variables');
      return new Response(JSON.stringify({ 
        error: 'OpenAI API key not configured. Please check your Supabase Edge Function secrets.' 
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

    console.log('Scan data retrieved successfully:', scan);

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

    // Prepare findings summary
    const findingsSummary = findings && findings.length > 0 
      ? findings.map(finding => 
          `Port ${finding.port}: ${finding.service_name} ${finding.service_version || ''} ${finding.cve_id ? `(CVE: ${finding.cve_id})` : ''}`
        ).join('\n')
      : 'No vulnerabilities found - all scanned services appear to be secure.';

    // Generate AI report
    const prompt = `Generate a security scan report for target: ${scan.target}

Scan findings:
${findingsSummary}

Please provide:
1. Executive Summary (2-3 sentences in plain language)
2. Risk Assessment (overall risk level: Low/Medium/High)
3. Detailed Findings (explain each vulnerability in simple terms)
4. Recommended Actions (specific steps to fix issues)

Use simple, non-technical language that business stakeholders can understand. Focus on the impact and solutions rather than technical jargon.`;

    console.log('Calling OpenAI API with gpt-4o-mini...');
    console.log('Request payload size:', JSON.stringify({
      model: 'gpt-4o-mini',
      messages: [
        { role: 'system', content: 'You are a cybersecurity expert who explains technical findings in simple, business-friendly language.' },
        { role: 'user', content: prompt }
      ],
      max_tokens: 2000,
      temperature: 0.3,
    }).length, 'characters');

    const openAIResponse = await fetch('https://api.openai.com/v1/chat/completions', {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${openAIApiKey}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        model: 'gpt-4o-mini',
        messages: [
          { role: 'system', content: 'You are a cybersecurity expert who explains technical findings in simple, business-friendly language.' },
          { role: 'user', content: prompt }
        ],
        max_tokens: 2000,
        temperature: 0.3,
      }),
    });

    console.log('OpenAI response status:', openAIResponse.status);
    console.log('OpenAI response headers:', Object.fromEntries(openAIResponse.headers.entries()));

    if (!openAIResponse.ok) {
      const errorText = await openAIResponse.text();
      console.error('OpenAI API error - Status:', openAIResponse.status);
      console.error('OpenAI API error - Response:', errorText);
      
      let errorMessage = `OpenAI API error (${openAIResponse.status})`;
      let userFriendlyMessage = 'Failed to generate report using AI';
      
      try {
        const errorData = JSON.parse(errorText);
        console.error('Parsed OpenAI error:', errorData);
        
        if (errorData.error?.message) {
          errorMessage = errorData.error.message;
          
          // Provide user-friendly messages for common errors
          if (errorData.error.code === 'insufficient_quota') {
            userFriendlyMessage = 'OpenAI API quota exceeded. Please check your OpenAI billing and usage limits.';
          } else if (errorData.error.code === 'invalid_api_key') {
            userFriendlyMessage = 'Invalid OpenAI API key. Please check your API key configuration.';
          } else if (errorData.error.code === 'rate_limit_exceeded') {
            userFriendlyMessage = 'OpenAI API rate limit exceeded. Please try again in a few minutes.';
          }
        }
      } catch (e) {
        console.error('Failed to parse OpenAI error response:', e);
        errorMessage += `: ${errorText}`;
      }
      
      return new Response(JSON.stringify({ 
        error: userFriendlyMessage,
        details: errorMessage,
        technical_details: errorText 
      }), {
        status: 500,
        headers: { ...corsHeaders, 'Content-Type': 'application/json' },
      });
    }

    const aiData = await openAIResponse.json();
    console.log('OpenAI response structure:', Object.keys(aiData));
    
    if (!aiData.choices || !aiData.choices[0] || !aiData.choices[0].message) {
      console.error('Unexpected OpenAI response structure:', aiData);
      return new Response(JSON.stringify({ 
        error: 'Unexpected response from OpenAI API',
        details: 'Response structure was not as expected'
      }), {
        status: 500,
        headers: { ...corsHeaders, 'Content-Type': 'application/json' },
      });
    }
    
    const reportContent = aiData.choices[0].message.content;
    console.log('AI report generated successfully, length:', reportContent.length);

    // Store the report
    console.log('Storing report in database...');
    const { error: reportError } = await supabase
      .from('reports')
      .upsert({
        scan_id: scanId,
        summary: reportContent,
        fix_recommendations: extractRecommendations(reportContent),
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
    console.error('Error stack trace:', error.stack);
    return new Response(JSON.stringify({ 
      error: 'Internal server error',
      details: error.message,
      stack: error.stack 
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
