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

    // Check if user already exists in auth
    const { data: existingAuthUsers } = await supabaseClient.auth.admin.listUsers();
    const existingAuthUser = existingAuthUsers?.users?.find(u => u.email === email);

    let newUser;
    
    if (existingAuthUser) {
      // User already exists in auth, just use the existing user
      console.log('User already exists in auth, reusing existing user:', existingAuthUser.id);
      newUser = { user: existingAuthUser };
    } else {
      // Generate a temporary password
      const tempPassword = crypto.randomUUID();

      // Create user with temporary password
      const { data: createdUser, error: createError } = await supabaseClient.auth.admin.createUser({
        email,
        password: tempPassword,
        email_confirm: false,
      });

      if (createError) {
        throw createError;
      }
      
      newUser = createdUser;
    }

    // Use the actual Lovable project URL for redirect
    const redirectUrl = `https://2f7ebd3f-a3b3-449b-94ac-f2a2c2d67068.lovableproject.com/set-password`;
    
    console.log('Redirect URL for password setup:', redirectUrl);
    
    // Use Supabase's built-in password recovery email (same as "Forgot Your Password")
    // This will automatically send the recovery email using Supabase's email service
    const { error: recoveryError } = await supabaseClient.auth.resetPasswordForEmail(email, {
      redirectTo: redirectUrl,
    });

    if (recoveryError) {
      console.error('Error sending password recovery email:', recoveryError);
      throw recoveryError;
    }

    console.log('Password recovery email sent successfully via Supabase email service');

    // Check if profile already exists for this email (orphaned record)
    const { data: existingProfile } = await supabaseClient
      .from('users')
      .select('user_id')
      .eq('email', email)
      .single();

    if (existingProfile) {
      // Update existing profile with new auth user ID
      const { error: updateError } = await supabaseClient
        .from('users')
        .update({
          user_id: newUser.user.id,
          name,
          password_hash: 'managed_by_auth',
        })
        .eq('email', email);

      if (updateError) {
        await supabaseClient.auth.admin.deleteUser(newUser.user.id);
        throw updateError;
      }
    } else {
      // Create new profile
      const { error: profileError } = await supabaseClient
        .from('users')
        .insert({
          user_id: newUser.user.id,
          email,
          name,
          password_hash: 'managed_by_auth',
        });

      if (profileError) {
        await supabaseClient.auth.admin.deleteUser(newUser.user.id);
        throw profileError;
      }
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
