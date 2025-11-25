
import React, { useState, useEffect } from 'react';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Switch } from '@/components/ui/switch';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import { Separator } from '@/components/ui/separator';
import { supabase } from '@/integrations/supabase/client';
import { useToast } from '@/hooks/use-toast';
import { RefreshCw, Save } from 'lucide-react';
import { useAuth } from '@/contexts/AuthContext';
import { useQuery } from '@tanstack/react-query';

export const Settings = () => {
  const { toast } = useToast();
  const { user } = useAuth();
  const [emailNotifications, setEmailNotifications] = useState(true);
  const [reportEmail, setReportEmail] = useState('admin@company.com');
  const [scanTimeout, setScanTimeout] = useState('60');
  const [consultantId, setConsultantId] = useState<string>('');
  const [isSavingConsultant, setIsSavingConsultant] = useState(false);

  // Fetch user's current consultant
  const { data: userData } = useQuery({
    queryKey: ['user-consultant', user?.id],
    queryFn: async () => {
      if (!user) return null;
      console.log('🔍 Fetching consultant for user:', user.id);
      const { data, error } = await supabase
        .from('users')
        .select('consultant_id')
        .eq('user_id', user.id)
        .single();
      
      if (error) {
        console.error('❌ Error fetching user consultant:', error);
        throw error;
      }
      console.log('✅ User consultant data:', data);
      return data;
    },
    enabled: !!user,
  });

  // Fetch all consultants and admins
  const { data: consultants } = useQuery({
    queryKey: ['consultants-and-admins'],
    queryFn: async () => {
      console.log('🔍 Fetching consultants and admins...');
      
      // First, get all user_ids with consultant or admin roles
      const { data: roleData, error: roleError } = await supabase
        .from('user_roles')
        .select('user_id')
        .in('role', ['consultant', 'admin']);
      
      if (roleError) {
        console.error('❌ Error fetching roles:', roleError);
        throw roleError;
      }
      
      console.log('📋 Role data:', roleData);
      
      if (!roleData || roleData.length === 0) {
        console.log('⚠️ No consultants or admins found');
        return [];
      }
      
      // Get unique user_ids
      const userIds = [...new Set(roleData.map(r => r.user_id))];
      console.log('👥 User IDs to fetch:', userIds);
      
      // Then fetch user details
      const { data: userData, error: userError } = await supabase
        .from('users')
        .select('user_id, email, name')
        .in('user_id', userIds);
      
      if (userError) {
        console.error('❌ Error fetching users:', userError);
        throw userError;
      }
      
      console.log('✅ Consultants fetched:', userData);
      return userData || [];
    },
  });

  useEffect(() => {
    console.log('📌 Setting consultant ID from userData:', userData);
    if (userData?.consultant_id) {
      console.log('✅ Setting consultant ID to:', userData.consultant_id);
      setConsultantId(userData.consultant_id);
    } else {
      console.log('⚠️ No consultant_id in userData, setting to empty');
      setConsultantId('');
    }
  }, [userData]);

  const handleSaveConsultant = async () => {
    if (!user) return;
    
    setIsSavingConsultant(true);
    try {
      const { error } = await supabase
        .from('users')
        .update({ consultant_id: consultantId || null })
        .eq('user_id', user.id);

      if (error) throw error;

      toast({
        title: "Settings Saved",
        description: "Your consultant preference has been updated.",
      });
    } catch (error) {
      console.error('Error saving consultant:', error);
      toast({
        title: "Save Failed",
        description: "Failed to save consultant preference. Please try again.",
        variant: "destructive",
      });
    } finally {
      setIsSavingConsultant(false);
    }
  };


  return (
    <>
      <div className="space-y-6">
        <div>
          <h1 className="text-3xl font-bold text-slate-900">Settings</h1>
          <p className="text-slate-600 mt-1">Configure your vulnerability scanner preferences</p>
        </div>

        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
          <Card>
            <CardHeader>
              <CardTitle>Consultant Assignment</CardTitle>
            </CardHeader>
            <CardContent className="space-y-6">
              <div>
                <Label htmlFor="consultant">Your Assigned Consultant</Label>
                <Select value={consultantId || 'none'} onValueChange={(value) => {
                  console.log('🎯 Consultant selected:', value);
                  setConsultantId(value === 'none' ? '' : value);
                }}>
                  <SelectTrigger className="mt-1 bg-white">
                    <SelectValue placeholder="Select a consultant" />
                  </SelectTrigger>
                  <SelectContent className="bg-white z-50">
                    <SelectItem value="none">None</SelectItem>
                    {consultants?.map((consultant: any) => (
                      <SelectItem key={consultant.user_id} value={consultant.user_id}>
                        {consultant.name || consultant.email}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
                <p className="text-xs text-muted-foreground mt-1">
                  Your consultant will review and approve all AI-generated security reports
                </p>
                {consultants && consultants.length === 0 && (
                  <p className="text-xs text-red-600 mt-1">
                    ⚠️ No consultants found. Try clicking "Sync User Profiles" below.
                  </p>
                )}
              </div>
              <Button 
                onClick={handleSaveConsultant}
                disabled={isSavingConsultant}
                className="w-full"
              >
                {isSavingConsultant ? (
                  <>
                    <RefreshCw className="mr-2 h-4 w-4 animate-spin" />
                    Saving...
                  </>
                ) : (
                  <>
                    <Save className="mr-2 h-4 w-4" />
                    Save Consultant
                  </>
                )}
              </Button>
            </CardContent>
          </Card>

          <Card>
            <CardHeader>
              <CardTitle>Notification Settings</CardTitle>
            </CardHeader>
            <CardContent className="space-y-6">
              <div className="flex items-center justify-between">
                <div className="space-y-0.5">
                  <Label className="text-base font-medium">Email Notifications</Label>
                  <div className="text-sm text-slate-600">
                    Receive email alerts for completed scans and critical findings
                  </div>
                </div>
                <Switch
                  checked={emailNotifications}
                  onCheckedChange={setEmailNotifications}
                />
              </div>

              <Separator />

              <div>
                <Label htmlFor="report-email" className="text-sm font-medium">
                  Report Email Address
                </Label>
                <Input
                  id="report-email"
                  value={reportEmail}
                  onChange={(e) => setReportEmail(e.target.value)}
                  placeholder="admin@company.com"
                  className="mt-1"
                />
                <p className="text-xs text-slate-600 mt-1">
                  Primary email for receiving scan reports and alerts
                </p>
              </div>
            </CardContent>
          </Card>

          <Card>
            <CardHeader>
              <CardTitle>Scan Configuration</CardTitle>
            </CardHeader>
            <CardContent className="space-y-6">
              <div>
                <Label htmlFor="scan-timeout" className="text-sm font-medium">
                  Default Scan Timeout (minutes)
                </Label>
                <Select value={scanTimeout} onValueChange={setScanTimeout}>
                  <SelectTrigger className="mt-1">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="30">30 minutes</SelectItem>
                    <SelectItem value="60">60 minutes</SelectItem>
                    <SelectItem value="120">2 hours</SelectItem>
                    <SelectItem value="240">4 hours</SelectItem>
                  </SelectContent>
                </Select>
                <p className="text-xs text-slate-600 mt-1">
                  Maximum time to wait for scan completion
                </p>
              </div>

              <Separator />

              <div>
                <Label className="text-sm font-medium mb-3 block">Risk Thresholds</Label>
                <div className="space-y-4">
                  <div className="flex items-center justify-between">
                    <span className="text-sm text-slate-600">Critical (CVSS Score)</span>
                    <div className="flex items-center space-x-2">
                      <span className="text-sm">≥ 9.0</span>
                      <div className="w-4 h-4 bg-red-500 rounded"></div>
                    </div>
                  </div>
                  <div className="flex items-center justify-between">
                    <span className="text-sm text-slate-600">Medium (CVSS Score)</span>
                    <div className="flex items-center space-x-2">
                      <span className="text-sm">4.0 - 8.9</span>
                      <div className="w-4 h-4 bg-yellow-500 rounded"></div>
                    </div>
                  </div>
                  <div className="flex items-center justify-between">
                    <span className="text-sm text-slate-600">Low (CVSS Score)</span>
                    <div className="flex items-center space-x-2">
                      <span className="text-sm">&lt; 4.0</span>
                      <div className="w-4 h-4 bg-green-500 rounded"></div>
                    </div>
                  </div>
                </div>
              </div>
            </CardContent>
          </Card>

          <Card>
            <CardHeader>
              <CardTitle>Data & Privacy</CardTitle>
            </CardHeader>
            <CardContent className="space-y-6">
              <div>
                <Label className="text-sm font-medium">Data Retention</Label>
                <p className="text-sm text-slate-600 mt-1">
                  Scan results are retained for 12 months. Critical findings are archived indefinitely.
                </p>
              </div>

              <Separator />

              <div>
                <Label className="text-sm font-medium">Export Data</Label>
                <p className="text-sm text-slate-600 mt-1 mb-3">
                  Download all your scan data and reports
                </p>
                <Button variant="outline" size="sm">
                  Export All Data
                </Button>
              </div>

              <Separator />

              <div>
                <Label className="text-sm font-medium text-red-600">Danger Zone</Label>
                <p className="text-sm text-slate-600 mt-1 mb-3">
                  Permanently delete all scan data and reports
                </p>
                <Button variant="destructive" size="sm">
                  Delete All Data
                </Button>
              </div>
            </CardContent>
          </Card>

          <Card>
            <CardHeader>
              <CardTitle>API Configuration</CardTitle>
            </CardHeader>
            <CardContent className="space-y-6">
              <div>
                <Label htmlFor="api-key" className="text-sm font-medium">
                  API Key
                </Label>
                <div className="flex space-x-2 mt-1">
                  <Input
                    id="api-key"
                    value="sk-••••••••••••••••••••••••••••••••"
                    readOnly
                    className="flex-1"
                  />
                  <Button variant="outline" size="sm">
                    Regenerate
                  </Button>
                </div>
                <p className="text-xs text-slate-600 mt-1">
                  Use this API key to integrate with external systems
                </p>
              </div>

              <Separator />

              <div>
                <Label className="text-sm font-medium">Rate Limits</Label>
                <div className="text-sm text-slate-600 mt-1 space-y-1">
                  <div>• 100 API requests per hour</div>
                  <div>• 10 concurrent scans maximum</div>
                  <div>• 1000 targets per scan</div>
                </div>
              </div>
            </CardContent>
          </Card>
        </div>

        <div className="flex justify-end">
          <Button className="bg-blue-600 hover:bg-blue-700">
            Save Settings
          </Button>
        </div>
      </div>
    </>
  );
};
