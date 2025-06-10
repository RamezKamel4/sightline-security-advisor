
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
    
    // Get OpenAI API key with better debugging
    const openAIApiKey = Deno.env.get('OPENAI_API_KEY');
    
    console.log('Environment variables check:');
    console.log('- OPENAI_API_KEY exists:', !!openAIApiKey);
    if (openAIApiKey) {
      console.log('- API key length:', openAIApiKey.length);
      console.log('- API key starts with:', openAIApiKey.substring(0, 7) + '...');
      console.log('- API key format check (should start with sk-):', openAIApiKey.startsWith('sk-'));
    }

    if (!openAIApiKey) {
      console.error('OpenAI API key not found');
      return new Response(JSON.stringify({ 
        error: 'OpenAI API key not configured in Supabase secrets. Please add OPENAI_API_KEY to your project secrets.' 
      }), {
        status: 500,
        headers: { ...corsHeaders, 'Content-Type': 'application/json' },
      });
    }

    if (!openAIApiKey.startsWith('sk-')) {
      console.error('Invalid OpenAI API key format');
      return new Response(JSON.stringify({ 
        error: 'Invalid OpenAI API key format. Key should start with "sk-"' 
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

    console.log('Making OpenAI API request...');
    console.log('Using model: gpt-4o-mini');
    console.log('Request payload preview:', {
      model: 'gpt-4o-mini',
      messages: 'Generated content',
      max_tokens: 2000,
      temperature: 0.3,
    });

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
      console.error('OpenAI API error - Full response:', errorText);
      
      let errorData;
      try {
        errorData = JSON.parse(errorText);
        console.error('Parsed OpenAI error:', errorData);
      } catch (e) {
        console.error('Failed to parse OpenAI error response:', e);
      }
      
      // Handle specific error cases
      if (openAIResponse.status === 401) {
        return new Response(JSON.stringify({ 
          error: 'Invalid OpenAI API key. Please check your API key in Supabase secrets.',
          details: 'Authentication failed with OpenAI API'
        }), {
          status: 500,
          headers: { ...corsHeaders, 'Content-Type': 'application/json' },
        });
      }
      
      if (openAIResponse.status === 429) {
        const quotaError = errorData?.error?.code === 'insufficient_quota';
        const rateLimitError = errorData?.error?.code === 'rate_limit_exceeded';
        
        if (quotaError) {
          return new Response(JSON.stringify({ 
            error: 'OpenAI API quota exceeded. Please add credits to your OpenAI account or upgrade your plan.',
            details: 'Your OpenAI account has reached its usage limits'
          }), {
            status: 500,
            headers: { ...corsHeaders, 'Content-Type': 'application/json' },
          });
        }
        
        if (rateLimitError) {
          return new Response(JSON.stringify({ 
            error: 'OpenAI API rate limit exceeded. Please try again in a few minutes.',
            details: 'Too many requests to OpenAI API'
          }), {
            status: 500,
            headers: { ...corsHeaders, 'Content-Type': 'application/json' },
          });
        }
      }
      
      return new Response(JSON.stringify({ 
        error: `OpenAI API error (${openAIResponse.status})`,
        details: errorData?.error?.message || errorText,
        raw_error: errorText
      }), {
        status: 500,
        headers: { ...corsHeaders, 'Content-Type': 'application/json' },
      });
    }

    const aiData = await openAIResponse.json();
    console.log('OpenAI response received successfully');
    
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
