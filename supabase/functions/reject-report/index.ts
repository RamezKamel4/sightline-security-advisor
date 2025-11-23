import { serve } from "https://deno.land/std@0.168.0/http/server.ts";
import { createClient } from "https://esm.sh/@supabase/supabase-js@2.50.0";

const corsHeaders = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Headers': 'authorization, x-client-info, apikey, content-type',
};

serve(async (req) => {
  if (req.method === 'OPTIONS') {
    return new Response(null, { headers: corsHeaders });
  }

  try {
    const supabaseClient = createClient(
      Deno.env.get('SUPABASE_URL') ?? '',
      Deno.env.get('SUPABASE_ANON_KEY') ?? '',
      {
        global: {
          headers: { Authorization: req.headers.get('Authorization')! },
        },
      }
    );

    // Verify user is a consultant
    const { data: { user }, error: userError } = await supabaseClient.auth.getUser();
    if (userError || !user) {
      return new Response(JSON.stringify({ error: 'Unauthorized' }), {
        status: 401,
        headers: { ...corsHeaders, 'Content-Type': 'application/json' },
      });
    }

    const { data: roles } = await supabaseClient
      .from('user_roles')
      .select('role')
      .eq('user_id', user.id);

    const isConsultant = roles?.some(r => r.role === 'consultant' || r.role === 'admin');
    if (!isConsultant) {
      return new Response(JSON.stringify({ error: 'Only consultants can reject reports' }), {
        status: 403,
        headers: { ...corsHeaders, 'Content-Type': 'application/json' },
      });
    }

    const { reportId, notes } = await req.json();

    if (!notes || notes.trim() === '') {
      return new Response(JSON.stringify({ error: 'Rejection notes are required' }), {
        status: 400,
        headers: { ...corsHeaders, 'Content-Type': 'application/json' },
      });
    }

    // Update report status
    const { data: report, error: updateError } = await supabaseClient
      .from('reports')
      .update({
        status: 'rejected',
        reviewed_at: new Date().toISOString(),
        consultant_id: user.id,
        review_notes: notes,
      })
      .eq('report_id', reportId)
      .select()
      .single();

    if (updateError) {
      console.error('Error rejecting report:', updateError);
      return new Response(JSON.stringify({ error: updateError.message }), {
        status: 500,
        headers: { ...corsHeaders, 'Content-Type': 'application/json' },
      });
    }

    // Log to audit trail
    await supabaseClient
      .from('report_audit_log')
      .insert({
        report_id: reportId,
        action: 'rejected',
        performed_by: user.id,
        notes,
      });

    console.log('Report rejected:', reportId);
    console.log('🔄 Automatically regenerating report with consultant feedback...');

    // Automatically regenerate the report with consultant feedback
    try {
      const { data: regenerateData, error: regenerateError } = await supabaseClient.functions.invoke('generate-report', {
        body: { 
          scanId: report.scan_id,
          rejectionFeedback: notes 
        }
      });

      if (regenerateError) {
        console.error('❌ Error regenerating report:', regenerateError);
        // Don't fail the rejection if regeneration fails - just log it
      } else {
        console.log('✅ Report regeneration initiated successfully');
      }
    } catch (regenerateError) {
      console.error('❌ Failed to trigger report regeneration:', regenerateError);
      // Continue - rejection was successful even if regeneration failed
    }

    return new Response(JSON.stringify({ success: true, report, regenerating: true }), {
      headers: { ...corsHeaders, 'Content-Type': 'application/json' },
    });
  } catch (error) {
    console.error('Error in reject-report function:', error);
    return new Response(JSON.stringify({ error: error.message }), {
      status: 500,
      headers: { ...corsHeaders, 'Content-Type': 'application/json' },
    });
  }
});
