
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
    
    // Try different possible names for the OpenAI API key
    const openAIApiKey = Deno.env.get('OPENAI_API_KEY') || 
                         Deno.env.get('OPENAI_API_KEY_GPT_4') ||
                         Deno.env.get('OPENAI_KEY');

    console.log('Available env vars:', Object.keys(Deno.env.toObject()));
    console.log('OpenAI API key found:', !!openAIApiKey);

    if (!openAIApiKey) {
      console.error('OpenAI API key not found in environment variables');
      throw new Error('OpenAI API key not configured. Please set OPENAI_API_KEY in Supabase Edge Function secrets.');
    }

    console.log('Fetching scan data for scanId:', scanId);

    // Get scan details and findings
    const { data: scan, error: scanError } = await supabase
      .from('scans')
      .select('*')
      .eq('scan_id', scanId)
      .single();

    if (scanError) {
      console.error('Scan fetch error:', scanError);
      throw new Error('Scan not found');
    }

    console.log('Scan data retrieved:', scan);

    const { data: findings, error: findingsError } = await supabase
      .from('findings')
      .select('*')
      .eq('scan_id', scanId);

    if (findingsError) {
      console.error('Findings fetch error:', findingsError);
      throw new Error('Failed to fetch findings');
    }

    console.log('Findings retrieved:', findings?.length || 0, 'findings');

    // Prepare findings summary for AI
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

    console.log('Calling OpenAI API...');

    const response = await fetch('https://api.openai.com/v1/chat/completions', {
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

    if (!response.ok) {
      const errorText = await response.text();
      console.error('OpenAI API error:', response.status, errorText);
      throw new Error(`OpenAI API error: ${response.status} - ${errorText}`);
    }

    const aiData = await response.json();
    const reportContent = aiData.choices[0].message.content;

    console.log('AI report generated successfully');

    // Store the report
    const { error: reportError } = await supabase
      .from('reports')
      .insert({
        scan_id: scanId,
        summary: reportContent,
        fix_recommendations: reportContent // For now, using the same content
      });

    if (reportError) {
      console.error('Report storage error:', reportError);
      throw new Error('Failed to save report');
    }

    console.log('Report saved to database successfully');

    return new Response(JSON.stringify({ success: true, report: reportContent }), {
      headers: { ...corsHeaders, 'Content-Type': 'application/json' },
    });

  } catch (error) {
    console.error('Error generating report:', error);
    return new Response(JSON.stringify({ error: error.message }), {
      status: 500,
      headers: { ...corsHeaders, 'Content-Type': 'application/json' },
    });
  }
});
