import { createClient } from 'https://esm.sh/@supabase/supabase-js@2.50.0';

const corsHeaders = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Headers': 'authorization, x-client-info, apikey, content-type',
};

interface ScheduledScan {
  id: string;
  user_id: string;
  target: string;
  profile: string;
  scan_depth: string;
  frequency: string;
  scheduled_time: string;
}

Deno.serve(async (req) => {
  if (req.method === 'OPTIONS') {
    return new Response(null, { headers: corsHeaders });
  }

  try {
    console.log('🔍 Checking for scheduled scans...');

    const supabaseClient = createClient(
      Deno.env.get('SUPABASE_URL') ?? '',
      Deno.env.get('SUPABASE_SERVICE_ROLE_KEY') ?? '',
      {
        auth: {
          autoRefreshToken: false,
          persistSession: false
        }
      }
    );

    // Get all due scheduled scans
    const { data: dueScans, error: fetchError } = await supabaseClient
      .rpc('get_due_scheduled_scans');

    if (fetchError) {
      console.error('❌ Error fetching due scans:', fetchError);
      throw fetchError;
    }

    if (!dueScans || dueScans.length === 0) {
      console.log('✅ No scheduled scans due at this time');
      return new Response(
        JSON.stringify({ message: 'No scans due', processed: 0 }),
        { headers: { ...corsHeaders, 'Content-Type': 'application/json' } }
      );
    }

    console.log(`📋 Found ${dueScans.length} due scans`);
    const results = [];

    // Process each due scan
    for (const scheduledScan of dueScans as ScheduledScan[]) {
      try {
        console.log(`🚀 Starting scan for ${scheduledScan.target} (user: ${scheduledScan.user_id})`);

        // Create a new scan record
        const { data: scan, error: scanError } = await supabaseClient
          .from('scans')
          .insert({
            target: scheduledScan.target,
            profile: scheduledScan.profile,
            scan_depth: scheduledScan.scan_depth,
            status: 'running',
            start_time: new Date().toISOString(),
            user_id: scheduledScan.user_id,
            host_info: null
          })
          .select()
          .single();

        if (scanError) {
          console.error(`❌ Error creating scan for ${scheduledScan.target}:`, scanError);
          results.push({ target: scheduledScan.target, success: false, error: scanError.message });
          continue;
        }

        console.log(`✅ Scan created: ${scan.scan_id} for ${scheduledScan.target}`);

        // Update the scheduled scan's last_run_at and next_run_at
        const now = new Date();
        const nextRun = calculateNextRun(now, scheduledScan.frequency);

        const { error: updateError } = await supabaseClient
          .from('scheduled_scans')
          .update({
            last_run_at: now.toISOString(),
            next_run_at: nextRun.toISOString()
          })
          .eq('id', scheduledScan.id);

        if (updateError) {
          console.error(`❌ Error updating scheduled scan ${scheduledScan.id}:`, updateError);
        }

        // Trigger the actual scan by calling the backend API
        // Note: This requires the FastAPI backend to be running
        try {
          const scanResponse = await fetch('http://localhost:8000/api/scan', {
            method: 'POST',
            headers: {
              'Content-Type': 'application/json',
            },
            body: JSON.stringify({
              ip_address: scheduledScan.target,
              nmap_args: getProfileArgs(scheduledScan.profile, scheduledScan.scan_depth),
              scan_profile: scheduledScan.profile,
              follow_up: false
            })
          });

          if (!scanResponse.ok) {
            throw new Error(`Backend scan failed: ${scanResponse.statusText}`);
          }

          const scanData = await scanResponse.json();

          // Update scan with results
          await supabaseClient
            .from('scans')
            .update({
              status: 'completed',
              end_time: new Date().toISOString(),
              nmap_cmd: scanData.nmap_cmd || null,
              nmap_output: scanData.nmap_output || null,
              host_info: scanData.host_info || null
            })
            .eq('scan_id', scan.scan_id);

          // Store findings if any
          if (scanData.results && scanData.results.length > 0) {
            const findings = scanData.results.map((result: any) => ({
              scan_id: scan.scan_id,
              host: result.host,
              port: result.port,
              state: result.state,
              service_name: result.service,
              service_version: result.version || 'unknown',
              cve_id: null,
              confidence: result.confidence || 0,
              raw_banner: result.raw_banner || null,
              headers: result.headers || null,
              tls_info: result.tls_info || null,
              proxy_detection: result.proxy_detection || null,
              detection_methods: result.detection_methods || null,
            }));

            await supabaseClient
              .from('findings')
              .insert(findings);
          }

          results.push({ target: scheduledScan.target, success: true, scan_id: scan.scan_id });
          console.log(`🎉 Scan completed successfully for ${scheduledScan.target}`);
        } catch (backendError) {
          console.error(`❌ Backend scan error for ${scheduledScan.target}:`, backendError);
          
          // Update scan status to failed
          await supabaseClient
            .from('scans')
            .update({
              status: 'failed',
              end_time: new Date().toISOString()
            })
            .eq('scan_id', scan.scan_id);

          results.push({ target: scheduledScan.target, success: false, error: (backendError as Error).message });
        }
      } catch (error) {
        console.error(`❌ Error processing scheduled scan for ${scheduledScan.target}:`, error);
        results.push({ target: scheduledScan.target, success: false, error: (error as Error).message });
      }
    }

    console.log(`✅ Processed ${results.length} scheduled scans`);
    return new Response(
      JSON.stringify({ 
        message: 'Scheduled scans processed', 
        processed: results.length,
        results 
      }),
      { headers: { ...corsHeaders, 'Content-Type': 'application/json' } }
    );
  } catch (error) {
    console.error('❌ Error in run-scheduled-scans:', error);
    return new Response(
      JSON.stringify({ error: (error as Error).message }),
      { 
        status: 500,
        headers: { ...corsHeaders, 'Content-Type': 'application/json' }
      }
    );
  }
});

function calculateNextRun(currentDate: Date, frequency: string): Date {
  const next = new Date(currentDate);
  
  switch (frequency) {
    case 'daily':
      next.setDate(next.getDate() + 1);
      break;
    case 'weekly':
      next.setDate(next.getDate() + 7);
      break;
    case 'monthly':
      next.setMonth(next.getMonth() + 1);
      break;
    default:
      next.setDate(next.getDate() + 1);
  }
  
  return next;
}

function getProfileArgs(profile: string, depth: string): string {
  const baseArgs: Record<string, string> = {
    'web-apps': '-p 80,443,8080,8443,3000,5000,8000,9000',
    'databases': '-p 1433,1521,3306,5432,6379,9042,11211,27017',
    'remote-access': '-p 22,23,3389,5900',
    'comprehensive': '-p-'
  };

  const depthArgs: Record<string, string> = {
    'fast': '-T4',
    'deep': '-T3 -sV',
    'aggressive': '-T4 -A -sV --script=default'
  };

  return `${baseArgs[profile] || baseArgs['comprehensive']} ${depthArgs[depth] || depthArgs['fast']}`;
}
