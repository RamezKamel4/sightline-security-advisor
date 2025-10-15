import React, { useState } from 'react';
import { Dialog, DialogContent, DialogHeader, DialogTitle } from '@/components/ui/dialog';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import { Card, CardContent } from '@/components/ui/card';
import { Separator } from '@/components/ui/separator';
import { useToast } from '@/components/ui/use-toast';
import { createScan } from '@/services/scanService';
import { ScanPermissionModal } from './ScanPermissionModal';

interface NewScanModalProps {
  isOpen: boolean;
  onClose: () => void;
  onScanCreated?: () => void;
}

export const NewScanModal = ({ isOpen, onClose, onScanCreated }: NewScanModalProps) => {
  const [target, setTarget] = useState('');
  const [scanProfile, setScanProfile] = useState('');
  const [schedule, setSchedule] = useState('now');
  const [isLoading, setIsLoading] = useState(false);
  const [showPermissionModal, setShowPermissionModal] = useState(false);
  const [pendingScanData, setPendingScanData] = useState<any>(null);
  const { toast } = useToast();

  const handleStartScan = async () => {
    if (!target || !scanProfile) {
      toast({
        title: "Missing Information",
        description: "Please fill in the target and scan profile.",
        variant: "destructive"
      });
      return;
    }

    const scanData = {
      target,
      scanProfile,
      scanDepth: 'fast',
      schedule,
    };

    // Show permission modal before starting
    setPendingScanData(scanData);
    setShowPermissionModal(true);
  };

  const handleConfirmScan = async () => {
    setShowPermissionModal(false);
    setIsLoading(true);
    
    try {
      const scanId = await createScan(pendingScanData);

      toast({
        title: "Scan Started",
        description: `Scan ${scanId} has been initiated successfully.`,
      });

      // Reset form
      setTarget('');
      setScanProfile('');
      setSchedule('now');
      setPendingScanData(null);
      
      onScanCreated?.();
      onClose();
    } catch (error) {
      console.error('Scan error:', error);
      toast({
        title: "Scan Failed",
        description: error instanceof Error ? error.message : "Failed to start scan",
        variant: "destructive"
      });
    } finally {
      setIsLoading(false);
    }
  };

  const handleCancelPermission = () => {
    setShowPermissionModal(false);
    setPendingScanData(null);
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
                    disabled={isLoading}
                  />
                  <p className="text-xs text-slate-600 mt-1">
                    Enter an IP address, domain name, or IP range (CIDR notation)
                  </p>
                </div>

                <div>
                  <Label className="text-sm font-medium">Scan Profile</Label>
                  <Select value={scanProfile} onValueChange={setScanProfile} disabled={isLoading}>
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
          <Button variant="outline" onClick={onClose} disabled={isLoading}>
            Cancel
          </Button>
          <Button 
            onClick={handleStartScan}
            disabled={!target || !scanProfile || isLoading}
            className="bg-blue-600 hover:bg-blue-700"
          >
            {isLoading ? 'Starting Scan...' : 'Start Scan'}
          </Button>
        </div>
      </DialogContent>
      
      <ScanPermissionModal
        isOpen={showPermissionModal}
        onConfirm={handleConfirmScan}
        onCancel={handleCancelPermission}
        scanType={scanProfile}
      />
    </Dialog>
  );
};
