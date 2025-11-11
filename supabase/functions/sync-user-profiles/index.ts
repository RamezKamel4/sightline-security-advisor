import { serve } from "https://deno.land/std@0.168.0/http/server.ts";
import { createClient } from "https://esm.sh/@supabase/supabase-js@2";

const corsHeaders = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Headers': 'authorization, x-client-info, apikey, content-type',
};

serve(async (req) => {
  if (req.method === 'OPTIONS') {
    return new Response(null, { headers: corsHeaders });
  }

  try {
    const supabaseUrl = Deno.env.get('SUPABASE_URL')!;
    const supabaseServiceKey = Deno.env.get('SUPABASE_SERVICE_ROLE_KEY')!;
    const supabase = createClient(supabaseUrl, supabaseServiceKey);

    // Get authorization header
    const authHeader = req.headers.get('Authorization');
    if (!authHeader) {
      throw new Error('No authorization header');
    }

    // Verify the user is authenticated and is an admin
    const token = authHeader.replace('Bearer ', '');
    const { data: { user }, error: userError } = await supabase.auth.getUser(token);
    
    if (userError || !user) {
      throw new Error('Unauthorized');
    }

    // Check if user is admin
    const { data: roles, error: rolesError } = await supabase
      .from('user_roles')
      .select('role')
      .eq('user_id', user.id);

    if (rolesError || !roles?.some(r => r.role === 'admin')) {
      throw new Error('Unauthorized - Admin access required');
    }

    // Get all auth users
    const { data: authUsers, error: authError } = await supabase.auth.admin.listUsers();
    
    if (authError) throw authError;

    // Get all existing profiles
    const { data: existingProfiles, error: profilesError } = await supabase
      .from('users')
      .select('user_id');

    if (profilesError) throw profilesError;

    const existingUserIds = new Set(existingProfiles?.map(p => p.user_id) || []);
    const missingProfiles = [];

    // Find users without profiles
    for (const authUser of authUsers.users) {
      if (!existingUserIds.has(authUser.id)) {
        missingProfiles.push({
          user_id: authUser.id,
          email: authUser.email || '',
          name: authUser.user_metadata?.name || authUser.email?.split('@')[0] || 'User',
          password_hash: '', // Empty since auth is handled by Supabase Auth
        });
      }
    }

    let synced = 0;
    let errors = [];

    // Insert missing profiles
    if (missingProfiles.length > 0) {
      const { data, error } = await supabase
        .from('users')
        .insert(missingProfiles)
        .select();

      if (error) {
        errors.push(error.message);
      } else {
        synced = data?.length || 0;
      }
    }

    return new Response(
      JSON.stringify({
        success: true,
        message: `Synced ${synced} user profiles`,
        missingProfiles: missingProfiles.length,
        synced,
        errors: errors.length > 0 ? errors : undefined,
      }),
      {
        headers: { ...corsHeaders, 'Content-Type': 'application/json' },
        status: 200,
      }
    );
  } catch (error) {
    console.error('Error syncing profiles:', error);
    return new Response(
      JSON.stringify({
        error: error instanceof Error ? error.message : 'Unknown error',
      }),
      {
        headers: { ...corsHeaders, 'Content-Type': 'application/json' },
        status: 400,
      }
    );
  }
});
