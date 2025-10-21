import { createClient } from 'https://esm.sh/@supabase/supabase-js@2.50.0';
import { corsHeaders } from '../_shared/cors.ts';

Deno.serve(async (req) => {
  if (req.method === 'OPTIONS') {
    return new Response(null, { headers: corsHeaders });
  }

  try {
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

    // Verify the requesting user is an admin
    const authHeader = req.headers.get('Authorization')!;
    const token = authHeader.replace('Bearer ', '');
    const { data: { user }, error: authError } = await supabaseClient.auth.getUser(token);

    if (authError || !user) {
      return new Response(JSON.stringify({ error: 'Unauthorized' }), {
        status: 401,
        headers: { ...corsHeaders, 'Content-Type': 'application/json' },
      });
    }

    // Check if user has admin role
    const { data: roles, error: rolesError } = await supabaseClient
      .from('user_roles')
      .select('role')
      .eq('user_id', user.id);

    if (rolesError || !roles?.some(r => r.role === 'admin')) {
      return new Response(JSON.stringify({ error: 'Forbidden: Admin access required' }), {
        status: 403,
        headers: { ...corsHeaders, 'Content-Type': 'application/json' },
      });
    }

    // Fetch all users using service role
    const { data: authUsers, error: usersError } = await supabaseClient.auth.admin.listUsers();
    
    if (usersError) {
      throw usersError;
    }

    // Get all user roles
    const { data: userRoles, error: userRolesError } = await supabaseClient
      .from('user_roles')
      .select('*');

    if (userRolesError) {
      throw userRolesError;
    }

    // Get user profiles
    const { data: profiles, error: profilesError } = await supabaseClient
      .from('users')
      .select('*');

    if (profilesError) {
      throw profilesError;
    }

    // Combine data
    const users = authUsers.users.map(authUser => ({
      id: authUser.id,
      email: authUser.email,
      created_at: authUser.created_at,
      last_sign_in_at: authUser.last_sign_in_at,
      roles: userRoles?.filter(r => r.user_id === authUser.id).map(r => r.role) || [],
      profile: profiles?.find(p => p.user_id === authUser.id),
    }));

    return new Response(JSON.stringify({ users }), {
      headers: { ...corsHeaders, 'Content-Type': 'application/json' },
    });

  } catch (error) {
    console.error('Error in list-users function:', error);
    return new Response(JSON.stringify({ error: error.message }), {
      status: 500,
      headers: { ...corsHeaders, 'Content-Type': 'application/json' },
    });
  }
});
