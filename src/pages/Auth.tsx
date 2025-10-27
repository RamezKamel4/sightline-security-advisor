
import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { useAuth } from '@/contexts/AuthContext';
import { supabase } from '@/integrations/supabase/client';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Shield, AlertCircle } from 'lucide-react';
import { useToast } from '@/hooks/use-toast';

const Auth = () => {
  const [isLogin, setIsLogin] = useState(true);
  const [isResetMode, setIsResetMode] = useState(false);
  const [isUpdatePasswordMode, setIsUpdatePasswordMode] = useState(false);
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [loading, setLoading] = useState(false);
  const [waitingForSession, setWaitingForSession] = useState(false);
  const { signIn, signUp, resetPassword, updatePassword, user, loading: authLoading, signOut } = useAuth();
  const navigate = useNavigate();
  const { toast } = useToast();

  // Detect password recovery from email link
  React.useEffect(() => {
    const hashParams = new URLSearchParams(window.location.hash.substring(1));
    const type = hashParams.get('type');
    
    if (type === 'recovery') {
      setWaitingForSession(true);
      setIsUpdatePasswordMode(true);
      setIsResetMode(false);
      setIsLogin(false);
    }
  }, []);

  // Wait for session to establish during recovery
  React.useEffect(() => {
    if (waitingForSession && !authLoading) {
      if (user) {
        // Session established successfully
        setWaitingForSession(false);
        // Now we can clear the hash
        window.history.replaceState(null, '', window.location.pathname);
      } else {
        // Session failed to establish
        setTimeout(() => {
          if (!user && waitingForSession) {
            toast({
              title: "Session Error",
              description: "Unable to establish password reset session. Please try clicking the reset link again.",
              variant: "destructive",
            });
            setWaitingForSession(false);
            setIsUpdatePasswordMode(false);
            setIsLogin(true);
          }
        }, 2000); // Give it 2 seconds to establish
      }
    }
  }, [waitingForSession, authLoading, user, toast]);

  // Sign out user if they navigate to auth page while authenticated
  // BUT don't sign out if this is a password recovery flow
  React.useEffect(() => {
    const hashParams = new URLSearchParams(window.location.hash.substring(1));
    const type = hashParams.get('type');
    
    if (!authLoading && user && type !== 'recovery' && !isUpdatePasswordMode) {
      signOut();
    }
  }, [user, authLoading, signOut, isUpdatePasswordMode]);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setLoading(true);

    try {
      if (isUpdatePasswordMode) {
        // Verify session exists before attempting password update
        if (!user) {
          toast({
            title: "Auth Session Missing",
            description: "Your session has expired. Please request a new password reset link.",
            variant: "destructive",
          });
          setIsUpdatePasswordMode(false);
          setIsLogin(true);
          setLoading(false);
          return;
        }

        // Validate passwords match
        if (password !== confirmPassword) {
          toast({
            title: "Password Mismatch",
            description: "Passwords do not match. Please try again.",
            variant: "destructive",
          });
          setLoading(false);
          return;
        }

        if (password.length < 6) {
          toast({
            title: "Password Too Short",
            description: "Password must be at least 6 characters long.",
            variant: "destructive",
          });
          setLoading(false);
          return;
        }

        const { error } = await updatePassword(password);
        if (error) {
          toast({
            title: "Update Password Error",
            description: error.message,
            variant: "destructive",
          });
        } else {
          toast({
            title: "Success!",
            description: "Password updated successfully. You can now sign in with your new password.",
          });
          setIsUpdatePasswordMode(false);
          setIsLogin(true);
          setPassword('');
          setConfirmPassword('');
        }
      } else if (isResetMode) {
        const { error } = await resetPassword(email);
        if (error) {
          toast({
            title: "Reset Password Error",
            description: error.message,
            variant: "destructive",
          });
        } else {
          toast({
            title: "Success!",
            description: "Password reset email sent. Please check your inbox.",
          });
          setIsResetMode(false);
        }
      } else {
        const { error } = isLogin 
          ? await signIn(email, password)
          : await signUp(email, password);

        if (error) {
          toast({
            title: "Authentication Error",
            description: error.message,
            variant: "destructive",
          });
        } else {
          if (isLogin) {
            navigate('/');
          } else {
            toast({
              title: "Success!",
              description: "Account created successfully. Please check your email to verify your account.",
            });
          }
        }
      }
    } catch (error) {
      toast({
        title: "Error",
        description: "An unexpected error occurred",
        variant: "destructive",
      });
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="min-h-screen bg-slate-50 flex items-center justify-center p-4">
      <div className="w-full max-w-md">
        <div className="text-center mb-8">
          <div className="flex items-center justify-center space-x-3 mb-4">
            <Shield className="h-12 w-12 text-blue-600" />
            <div>
              <h1 className="text-3xl font-bold text-slate-900">VulnScan AI</h1>
              <p className="text-slate-600">Security Scanner</p>
            </div>
          </div>
        </div>

        {waitingForSession ? (
          <Card>
            <CardContent className="pt-6">
              <div className="text-center py-8">
                <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-blue-600 mx-auto mb-4"></div>
                <p className="text-slate-600">Establishing secure session...</p>
              </div>
            </CardContent>
          </Card>
        ) : (
          <Card>
          <CardHeader>
            <CardTitle className="text-center">
              {isUpdatePasswordMode ? 'Update Password' : (isResetMode ? 'Reset Password' : (isLogin ? 'Sign In' : 'Create Account'))}
            </CardTitle>
          </CardHeader>
          <CardContent>
            <form onSubmit={handleSubmit} className="space-y-4">
              {!isUpdatePasswordMode && (
                <div>
                  <label htmlFor="email" className="block text-sm font-medium text-slate-700 mb-1">
                    Email
                  </label>
                  <Input
                    id="email"
                    type="email"
                    value={email}
                    onChange={(e) => setEmail(e.target.value)}
                    placeholder="Enter your email"
                    required
                  />
                </div>
              )}
              
              {!isResetMode && (
                <>
                  <div>
                    <label htmlFor="password" className="block text-sm font-medium text-slate-700 mb-1">
                      {isUpdatePasswordMode ? 'New Password' : 'Password'}
                    </label>
                    <Input
                      id="password"
                      type="password"
                      value={password}
                      onChange={(e) => setPassword(e.target.value)}
                      placeholder={isUpdatePasswordMode ? "Enter your new password" : "Enter your password"}
                      required
                      minLength={6}
                    />
                  </div>
                  
                  {isUpdatePasswordMode && (
                    <div>
                      <label htmlFor="confirmPassword" className="block text-sm font-medium text-slate-700 mb-1">
                        Confirm New Password
                      </label>
                      <Input
                        id="confirmPassword"
                        type="password"
                        value={confirmPassword}
                        onChange={(e) => setConfirmPassword(e.target.value)}
                        placeholder="Confirm your new password"
                        required
                        minLength={6}
                      />
                    </div>
                  )}
                </>
              )}

              <Button 
                type="submit" 
                className="w-full bg-blue-600 hover:bg-blue-700"
                disabled={loading}
              >
                {loading ? 'Processing...' : (isUpdatePasswordMode ? 'Update Password' : (isResetMode ? 'Send Reset Email' : (isLogin ? 'Sign In' : 'Create Account')))}
              </Button>
            </form>

            <div className="mt-6 text-center space-y-2">
              {!isResetMode && !isUpdatePasswordMode && (
                <>
                  <button
                    type="button"
                    onClick={() => setIsLogin(!isLogin)}
                    className="text-blue-600 hover:text-blue-800 text-sm block w-full"
                  >
                    {isLogin 
                      ? "Don't have an account? Sign up" 
                      : "Already have an account? Sign in"
                    }
                  </button>
                  
                  {isLogin && (
                    <button
                      type="button"
                      onClick={() => setIsResetMode(true)}
                      className="text-blue-600 hover:text-blue-800 text-sm"
                    >
                      Forgot your password?
                    </button>
                  )}
                </>
              )}
              
              {isResetMode && (
                <button
                  type="button"
                  onClick={() => {
                    setIsResetMode(false);
                    setPassword('');
                  }}
                  className="text-blue-600 hover:text-blue-800 text-sm"
                >
                  Back to sign in
                </button>
              )}
              
              {isUpdatePasswordMode && (
                <button
                  type="button"
                  onClick={() => {
                    setIsUpdatePasswordMode(false);
                    setIsLogin(true);
                    setPassword('');
                    setConfirmPassword('');
                  }}
                  className="text-blue-600 hover:text-blue-800 text-sm"
                >
                  Back to sign in
                </button>
              )}
            </div>

            {!isLogin && !isResetMode && !isUpdatePasswordMode && (
              <div className="mt-4 p-3 bg-blue-50 rounded-lg">
                <div className="flex items-start space-x-2">
                  <AlertCircle className="h-4 w-4 text-blue-600 mt-0.5" />
                  <p className="text-sm text-blue-800">
                    After signing up, please check your email to verify your account before signing in.
                  </p>
                </div>
              </div>
            )}
            
            {isResetMode && (
              <div className="mt-4 p-3 bg-blue-50 rounded-lg">
                <div className="flex items-start space-x-2">
                  <AlertCircle className="h-4 w-4 text-blue-600 mt-0.5" />
                  <p className="text-sm text-blue-800">
                    Enter your email address and we'll send you a link to reset your password.
                  </p>
                </div>
              </div>
            )}
            
            {isUpdatePasswordMode && (
              <div className="mt-4 p-3 bg-blue-50 rounded-lg">
                <div className="flex items-start space-x-2">
                  <AlertCircle className="h-4 w-4 text-blue-600 mt-0.5" />
                  <p className="text-sm text-blue-800">
                    Enter your new password below. It must be at least 6 characters long.
                  </p>
                </div>
              </div>
            )}
          </CardContent>
        </Card>
        )}
      </div>
    </div>
  );
};

export default Auth;
