import { createClient } from 'https://esm.sh/@supabase/supabase-js@2.50.0';
import { Resend } from 'npm:resend@4.0.0';
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

    // Generate password reset link with redirect to /set-password
    // Determine the correct redirect URL based on environment
    const supabaseUrl = Deno.env.get('SUPABASE_URL') ?? '';
    const projectId = supabaseUrl.split('//')[1]?.split('.')[0];
    const redirectUrl = `https://${projectId}.lovableproject.com/set-password`;
    
    console.log('Redirect URL for password setup:', redirectUrl);
    
    // Generate recovery link for password setup
    const { data: recoveryData, error: recoveryError } = await supabaseClient.auth.admin.generateLink({
      type: 'recovery',
      email,
      options: {
        redirectTo: redirectUrl,
      },
    });

    if (recoveryError) {
      console.error('Error generating recovery link:', recoveryError);
      throw recoveryError;
    }

    console.log('Generated password setup link:', recoveryData.properties.action_link);

    // Send email with password setup link using Resend (if API key is available)
    const resendApiKey = Deno.env.get('RESEND_API_KEY');
    
    if (resendApiKey) {
      try {
        const resend = new Resend(resendApiKey);
        
        const emailResponse = await resend.emails.send({
          from: 'VulnScan AI <admin@vulnscanai.com>',
          to: [email],
          subject: 'Set Your Password - VulnScan AI',
          html: `
            <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
              <h2 style="color: #333;">Welcome to VulnScan AI!</h2>
              <p>Hello ${name},</p>
              <p>An administrator has created an account for you. Please click the button below to set your password:</p>
              <div style="text-align: center; margin: 30px 0;">
                <a href="${recoveryData.properties.action_link}" 
                   style="background-color: #4F46E5; color: white; padding: 12px 30px; text-decoration: none; border-radius: 5px; display: inline-block;">
                  Set Your Password
                </a>
              </div>
              <p style="color: #666; font-size: 14px;">This link will expire in 24 hours.</p>
              <p style="color: #666; font-size: 14px;">If you didn't request this, please ignore this email.</p>
            </div>
          `,
        });
        
        console.log('Password setup email sent successfully:', emailResponse);
      } catch (emailError) {
        console.error('Error sending email:', emailError);
        // Continue even if email fails - link is logged for manual sending
      }
    } else {
      console.log('RESEND_API_KEY not configured - email not sent. Password setup link logged above.');
    }

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
