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

    // Get request body
    const { email, name, roles: userRoles } = await req.json();

    // Validate input
    if (!email || !name) {
      return new Response(JSON.stringify({ error: 'Email and name are required' }), {
        status: 400,
        headers: { ...corsHeaders, 'Content-Type': 'application/json' },
      });
    }

    // Get redirect URL for password setup
    const redirectUrl = `${Deno.env.get('SUPABASE_URL')}/auth/v1/verify`;

    // Invite user - this sends an email with a link to set password
    const { data: newUser, error: createError } = await supabaseClient.auth.admin.inviteUserByEmail(email, {
      redirectTo: redirectUrl,
    });

    if (createError) {
      throw createError;
    }

    // Create user profile
    const { error: profileError } = await supabaseClient
      .from('users')
      .insert({
        user_id: newUser.user.id,
        email,
        name,
        password_hash: 'managed_by_auth',
      });

    if (profileError) {
      // If profile creation fails, delete the auth user
      await supabaseClient.auth.admin.deleteUser(newUser.user.id);
      throw profileError;
    }

    // Assign roles if provided
    if (userRoles && Array.isArray(userRoles) && userRoles.length > 0) {
      const roleInserts = userRoles.map(role => ({
        user_id: newUser.user.id,
        role,
      }));

      const { error: rolesInsertError } = await supabaseClient
        .from('user_roles')
        .insert(roleInserts);

      if (rolesInsertError) {
        console.error('Error assigning roles:', rolesInsertError);
      }
    }

    return new Response(JSON.stringify({ 
      success: true,
      user: {
        id: newUser.user.id,
        email: newUser.user.email,
      }
    }), {
      headers: { ...corsHeaders, 'Content-Type': 'application/json' },
    });

  } catch (error) {
    console.error('Error in create-user function:', error);
    return new Response(JSON.stringify({ error: error.message }), {
      status: 500,
      headers: { ...corsHeaders, 'Content-Type': 'application/json' },
    });
  }
});
