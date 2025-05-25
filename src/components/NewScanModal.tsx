
import React, { useState } from 'react';
import { Dialog, DialogContent, DialogHeader, DialogTitle } from '@/components/ui/dialog';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import { RadioGroup, RadioGroupItem } from '@/components/ui/radio-group';
import { Card, CardContent } from '@/components/ui/card';
import { Separator } from '@/components/ui/separator';

interface NewScanModalProps {
  isOpen: boolean;
  onClose: () => void;
}

export const NewScanModal = ({ isOpen, onClose }: NewScanModalProps) => {
  const [target, setTarget] = useState('');
  const [scanProfile, setScanProfile] = useState('');
  const [scanDepth, setScanDepth] = useState('fast');
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [schedule, setSchedule] = useState('now');

  const handleStartScan = () => {
    console.log('Starting scan with:', {
      target,
      scanProfile,
      scanDepth,
      username: username || undefined,
      password: password || undefined,
      schedule,
    });
    onClose();
  };

  return (
    <Dialog open={isOpen} onOpenChange={onClose}>
      <DialogContent className="max-w-2xl max-h-[90vh] overflow-y-auto">
        <DialogHeader>
          <DialogTitle className="text-2xl font-bold">Configure New Scan</DialogTitle>
        </DialogHeader>
        
        <div className="space-y-6">
          <Card>
            <CardContent className="p-6">
              <div className="space-y-4">
                <div>
                  <Label htmlFor="target" className="text-sm font-medium">
                    Target (IP, Domain, or Range)
                  </Label>
                  <Input
                    id="target"
                    placeholder="e.g., 192.168.1.0/24 or example.com"
                    value={target}
                    onChange={(e) => setTarget(e.target.value)}
                    className="mt-1"
                  />
                  <p className="text-xs text-slate-600 mt-1">
                    Enter an IP address, domain name, or IP range (CIDR notation)
                  </p>
                </div>

                <div>
                  <Label className="text-sm font-medium">Scan Profile</Label>
                  <Select value={scanProfile} onValueChange={setScanProfile}>
                    <SelectTrigger className="mt-1">
                      <SelectValue placeholder="Select scan profile" />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value="web-apps">Web Applications (80, 443, 8080, 8443)</SelectItem>
                      <SelectItem value="databases">Databases (3306, 5432, 27017)</SelectItem>
                      <SelectItem value="remote-access">Remote Access (22, 3389, 1194)</SelectItem>
                      <SelectItem value="comprehensive">Comprehensive Scan (All Ports)</SelectItem>
                    </SelectContent>
                  </Select>
                </div>
              </div>
            </CardContent>
          </Card>

          <Card>
            <CardContent className="p-6">
              <div className="space-y-4">
                <Label className="text-sm font-medium">Scan Depth</Label>
                <RadioGroup value={scanDepth} onValueChange={setScanDepth}>
                  <div className="flex items-center space-x-2">
                    <RadioGroupItem value="fast" id="fast" />
                    <Label htmlFor="fast" className="cursor-pointer">
                      <div>
                        <div className="font-medium">Fast Scan</div>
                        <div className="text-xs text-slate-600">Quick port discovery (2-5 minutes)</div>
                      </div>
                    </Label>
                  </div>
                  <div className="flex items-center space-x-2">
                    <RadioGroupItem value="deep" id="deep" />
                    <Label htmlFor="deep" className="cursor-pointer">
                      <div>
                        <div className="font-medium">Deep Scan</div>
                        <div className="text-xs text-slate-600">Service detection and OS fingerprinting (10-20 minutes)</div>
                      </div>
                    </Label>
                  </div>
                  <div className="flex items-center space-x-2">
                    <RadioGroupItem value="aggressive" id="aggressive" />
                    <Label htmlFor="aggressive" className="cursor-pointer">
                      <div>
                        <div className="font-medium">Aggressive Scan</div>
                        <div className="text-xs text-slate-600">Comprehensive vulnerability detection (30+ minutes)</div>
                      </div>
                    </Label>
                  </div>
                </RadioGroup>
              </div>
            </CardContent>
          </Card>

          <Card>
            <CardContent className="p-6">
              <div className="space-y-4">
                <Label className="text-sm font-medium">Authentication (Optional)</Label>
                <div className="grid grid-cols-2 gap-4">
                  <div>
                    <Label htmlFor="username" className="text-xs text-slate-600">Username</Label>
                    <Input
                      id="username"
                      placeholder="Username"
                      value={username}
                      onChange={(e) => setUsername(e.target.value)}
                      className="mt-1"
                    />
                  </div>
                  <div>
                    <Label htmlFor="password" className="text-xs text-slate-600">Password</Label>
                    <Input
                      id="password"
                      type="password"
                      placeholder="Password"
                      value={password}
                      onChange={(e) => setPassword(e.target.value)}
                      className="mt-1"
                    />
                  </div>
                </div>
                <p className="text-xs text-slate-600">
                  Provide credentials for authenticated scanning (more thorough results)
                </p>
              </div>
            </CardContent>
          </Card>

          <Card>
            <CardContent className="p-6">
              <div className="space-y-4">
                <Label className="text-sm font-medium">Schedule</Label>
                <Select value={schedule} onValueChange={setSchedule}>
                  <SelectTrigger>
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="now">Run Now</SelectItem>
                    <SelectItem value="daily">Daily at Current Time</SelectItem>
                    <SelectItem value="weekly">Weekly at Current Time</SelectItem>
                    <SelectItem value="monthly">Monthly at Current Time</SelectItem>
                  </SelectContent>
                </Select>
              </div>
            </CardContent>
          </Card>
        </div>

        <Separator />

        <div className="flex justify-end space-x-3">
          <Button variant="outline" onClick={onClose}>
            Cancel
          </Button>
          <Button 
            onClick={handleStartScan}
            disabled={!target || !scanProfile}
            className="bg-blue-600 hover:bg-blue-700"
          >
            Start Scan
          </Button>
        </div>
      </DialogContent>
    </Dialog>
  );
};
