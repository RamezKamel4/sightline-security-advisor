
import React, { useState } from 'react';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Switch } from '@/components/ui/switch';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import { Separator } from '@/components/ui/separator';
import { supabase } from '@/integrations/supabase/client';
import { toast } from 'sonner';

export const Settings = () => {
  const [emailNotifications, setEmailNotifications] = useState(true);
  const [autoSchedule, setAutoSchedule] = useState(false);
  const [reportEmail, setReportEmail] = useState('admin@company.com');
  const [scanTimeout, setScanTimeout] = useState('60');
  const [isResettingCVE, setIsResettingCVE] = useState(false);

  const handleResetCVEEnrichment = async () => {
    setIsResettingCVE(true);
    try {
      // Reset cve_enriched flag for all scans
      const { error } = await supabase
        .from('scans')
        .update({ cve_enriched: false })
        .eq('cve_enriched', true);

      if (error) throw error;

      toast.success('CVE enrichment reset successfully. Run new scans or view existing scans to re-enrich with CVE data.');
    } catch (error) {
      console.error('Error resetting CVE enrichment:', error);
      toast.error('Failed to reset CVE enrichment');
    } finally {
      setIsResettingCVE(false);
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

              <div className="flex items-center justify-between">
                <div className="space-y-0.5">
                  <Label className="text-base font-medium">Auto-Schedule Scans</Label>
                  <div className="text-sm text-slate-600">
                    Automatically schedule recurring scans for saved targets
                  </div>
                </div>
                <Switch
                  checked={autoSchedule}
                  onCheckedChange={setAutoSchedule}
                />
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
              <CardTitle>CVE Database</CardTitle>
            </CardHeader>
            <CardContent className="space-y-6">
              <div>
                <Label className="text-sm font-medium">CVE Enrichment Status</Label>
                <p className="text-sm text-slate-600 mt-1">
                  Scans are automatically enriched with CVE data from the National Vulnerability Database (NVD).
                </p>
              </div>

              <Separator />

              <div>
                <Label className="text-sm font-medium">Reset CVE Enrichment</Label>
                <p className="text-sm text-slate-600 mt-1 mb-3">
                  Reset all scans to re-fetch fresh CVE data from NVD. Use this if CVE data seems outdated or incomplete.
                </p>
                <Button 
                  variant="outline" 
                  size="sm"
                  onClick={handleResetCVEEnrichment}
                  disabled={isResettingCVE}
                >
                  {isResettingCVE ? 'Resetting...' : 'Reset CVE Data'}
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
