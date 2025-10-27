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
  frequency: string;
  scheduled_time: string;
}

Deno.serve(async (req) => {
  if (req.method === 'OPTIONS') {
    return new Response(null, { headers: corsHeaders });
  }

  try {
    console.log('🔄 Checking for scheduled scans...');

    const supabaseUrl = Deno.env.get('SUPABASE_URL')!;
    const supabaseServiceKey = Deno.env.get('SUPABASE_SERVICE_ROLE_KEY')!;
    const supabase = createClient(supabaseUrl, supabaseServiceKey);

    const { data: dueScans, error: fetchError } = await supabase.rpc('get_due_scheduled_scans');

    if (fetchError) {
      console.error('❌ Error fetching due scans:', fetchError);
      throw fetchError;
    }

    if (!dueScans || dueScans.length === 0) {
      console.log('✅ No scans due at this time');
      return new Response(
        JSON.stringify({ message: 'No scans due', processedCount: 0 }),
        { headers: { ...corsHeaders, 'Content-Type': 'application/json' }, status: 200 }
      );
    }

    console.log(`📋 Found ${dueScans.length} scans to execute`);

    const results = [];
    for (const scheduledScan of dueScans as ScheduledScan[]) {
      try {
        console.log(`🚀 Starting scan for ${scheduledScan.target}`);

        const { data: newScan, error: createError } = await supabase
          .from('scans')
          .insert({
            target: scheduledScan.target,
            profile: scheduledScan.profile,
            status: 'running',
            start_time: new Date().toISOString(),
            user_id: scheduledScan.user_id,
            host_info: null,
          })
          .select()
          .single();

        if (createError) {
          console.error(`❌ Error creating scan for ${scheduledScan.target}:`, createError);
          results.push({ scheduled_scan_id: scheduledScan.id, success: false, error: createError.message });
          continue;
        }

        console.log(`✅ Created scan ${newScan.scan_id} for ${scheduledScan.target}`);

        const backendUrl = 'http://localhost:8000/api/scan';
        const scanResponse = await fetch(backendUrl, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            ip_address: scheduledScan.target,
            nmap_args: '',
            scan_profile: scheduledScan.profile,
          }),
        });

        if (!scanResponse.ok) {
          throw new Error(`Backend scan failed: ${scanResponse.statusText}`);
        }

        const scanData = await scanResponse.json();

        await supabase
          .from('scans')
          .update({
            status: 'completed',
            end_time: new Date().toISOString(),
            nmap_cmd: scanData.nmap_cmd,
            nmap_output: scanData.nmap_output,
            host_info: scanData.host_info || null,
          })
          .eq('scan_id', newScan.scan_id);

        if (scanData.results && scanData.results.length > 0) {
          const findingsToInsert = scanData.results.map((result: any) => ({
            scan_id: newScan.scan_id,
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

          await supabase.from('findings').insert(findingsToInsert);
        }

        const currentRunTime = new Date();
        const { data: nextRunData } = await supabase.rpc('calculate_next_run', {
          current_run: currentRunTime.toISOString(),
          freq: scheduledScan.frequency,
        });

        await supabase
          .from('scheduled_scans')
          .update({
            last_run_at: currentRunTime.toISOString(),
            next_run_at: nextRunData,
          })
          .eq('id', scheduledScan.id);

        console.log(`✅ Completed scheduled scan for ${scheduledScan.target}`);
        results.push({ scheduled_scan_id: scheduledScan.id, scan_id: newScan.scan_id, success: true });
      } catch (error) {
        console.error(`❌ Error processing scan for ${scheduledScan.target}:`, error);
        results.push({
          scheduled_scan_id: scheduledScan.id,
          success: false,
          error: error instanceof Error ? error.message : 'Unknown error',
        });
      }
    }

    console.log(`🎉 Processed ${results.length} scheduled scans`);

    return new Response(
      JSON.stringify({ message: 'Scheduled scans processed', processedCount: results.length, results }),
      { headers: { ...corsHeaders, 'Content-Type': 'application/json' }, status: 200 }
    );
  } catch (error) {
    console.error('❌ Error in run-scheduled-scans:', error);
    return new Response(
      JSON.stringify({ error: error instanceof Error ? error.message : 'Unknown error' }),
      { headers: { ...corsHeaders, 'Content-Type': 'application/json' }, status: 500 }
    );
  }
});
