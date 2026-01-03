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
    // Use anon key for auth check
    const supabaseClient = createClient(
      Deno.env.get('SUPABASE_URL') ?? '',
      Deno.env.get('SUPABASE_ANON_KEY') ?? '',
      {
        global: {
          headers: { Authorization: req.headers.get('Authorization')! },
        },
      }
    );
    
    // Use service role for data fetching (bypasses RLS)
    const supabaseAdmin = createClient(
      Deno.env.get('SUPABASE_URL') ?? '',
      Deno.env.get('SUPABASE_SERVICE_ROLE_KEY') ?? ''
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

    const isAdmin = roles?.some(r => r.role === 'admin');
    const isConsultant = roles?.some(r => r.role === 'consultant');
    
    if (!isAdmin && !isConsultant) {
      return new Response(JSON.stringify({ error: 'Only consultants can view pending reports' }), {
        status: 403,
        headers: { ...corsHeaders, 'Content-Type': 'application/json' },
      });
    }

    console.log(`User ${user.id} (admin: ${isAdmin}, consultant: ${isConsultant}) fetching pending reports`);

    // Build query - admins see all, consultants see only assigned
    let reportsQuery = supabaseAdmin
      .from('reports')
      .select('*')
      .eq('status', 'pending_review')
      .order('created_at', { ascending: false });

    // Consultants only see reports assigned to them
    if (!isAdmin) {
      reportsQuery = reportsQuery.eq('consultant_id', user.id);
    }

    const { data: reports, error: reportsError } = await reportsQuery;

    if (reportsError) {
      console.error('Error fetching pending reports:', reportsError);
      return new Response(JSON.stringify({ error: reportsError.message }), {
        status: 500,
        headers: { ...corsHeaders, 'Content-Type': 'application/json' },
      });
    }

    console.log('Fetched pending reports:', reports?.length || 0);

    // Manually fetch scan and user data for each report
    if (reports && reports.length > 0) {
      const enrichedReports = await Promise.all(
        reports.map(async (report) => {
          // Fetch scan data using service role
          const { data: scan } = await supabaseAdmin
            .from('scans')
            .select('scan_id, target, start_time, user_id')
            .eq('scan_id', report.scan_id)
            .maybeSingle();

          // Fetch user data using service role
          let userData = null;
          if (scan?.user_id) {
            const { data: user } = await supabaseAdmin
              .from('users')
              .select('user_id, name, email')
              .eq('user_id', scan.user_id)
              .maybeSingle();
            userData = user;
          }

          return {
            ...report,
            scans: scan ? {
              ...scan,
              users: userData
            } : null
          };
        })
      );

      return new Response(JSON.stringify({ reports: enrichedReports }), {
        headers: { ...corsHeaders, 'Content-Type': 'application/json' },
      });
    }

    return new Response(JSON.stringify({ reports }), {
      headers: { ...corsHeaders, 'Content-Type': 'application/json' },
    });
  } catch (error) {
    console.error('Error in get-pending-reports function:', error);
    return new Response(JSON.stringify({ error: error.message }), {
      status: 500,
      headers: { ...corsHeaders, 'Content-Type': 'application/json' },
    });
  }
});
