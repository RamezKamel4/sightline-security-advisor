
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
    const openAIApiKey = Deno.env.get('OPENAI_API_KEY');

    if (!openAIApiKey) {
      throw new Error('OpenAI API key not configured');
    }

    // Get scan details and findings
    const { data: scan, error: scanError } = await supabase
      .from('scans')
      .select('*')
      .eq('scan_id', scanId)
      .single();

    if (scanError) {
      throw new Error('Scan not found');
    }

    const { data: findings, error: findingsError } = await supabase
      .from('findings')
      .select('*')
      .eq('scan_id', scanId);

    if (findingsError) {
      throw new Error('Failed to fetch findings');
    }

    // Prepare findings summary for AI
    const findingsSummary = findings.map(finding => 
      `Port ${finding.port}: ${finding.service_name} ${finding.service_version || ''} ${finding.cve_id ? `(CVE: ${finding.cve_id})` : ''}`
    ).join('\n');

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

    const response = await fetch('https://api.openai.com/v1/chat/completions', {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${openAIApiKey}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        model: 'gpt-4',
        messages: [
          { role: 'system', content: 'You are a cybersecurity expert who explains technical findings in simple, business-friendly language.' },
          { role: 'user', content: prompt }
        ],
        max_tokens: 2000,
        temperature: 0.3,
      }),
    });

    const aiData = await response.json();
    const reportContent = aiData.choices[0].message.content;

    // Store the report
    const { error: reportError } = await supabase
      .from('reports')
      .insert({
        scan_id: scanId,
        summary: reportContent,
        fix_recommendations: reportContent // For now, using the same content
      });

    if (reportError) {
      throw new Error('Failed to save report');
    }

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
