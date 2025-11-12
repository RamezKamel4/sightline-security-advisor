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
    const supabaseAnonKey = Deno.env.get('SUPABASE_ANON_KEY')!;
    const supabaseServiceKey = Deno.env.get('SUPABASE_SERVICE_ROLE_KEY')!;

    // Get authorization header
    const authHeader = req.headers.get('Authorization');
    if (!authHeader) {
      throw new Error('No authorization header');
    }

    // Create user-authenticated client to verify admin role
    const userClient = createClient(supabaseUrl, supabaseAnonKey, {
      global: {
        headers: {
          Authorization: authHeader,
        },
      },
    });

    // Verify the user is authenticated
    const { data: { user }, error: userError } = await userClient.auth.getUser();
    
    if (userError || !user) {
      console.error('Auth error:', userError);
      throw new Error('Unauthorized');
    }

    console.log('Authenticated user:', user.id);

    // Check if user is admin using the has_role function
    const { data: isAdmin, error: roleCheckError } = await userClient
      .rpc('has_role', { _user_id: user.id, _role: 'admin' });

    console.log('Admin check result:', isAdmin, roleCheckError);

    if (roleCheckError || !isAdmin) {
      throw new Error('Unauthorized - Admin access required');
    }

    // Now use service role client for admin operations
    const supabase = createClient(supabaseUrl, supabaseServiceKey);

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
