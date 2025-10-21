
import React, { useState, useEffect } from 'react';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Input } from '@/components/ui/input';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import { Checkbox } from '@/components/ui/checkbox';
import { FileText, Download, Search, Filter, Eye, Loader2 } from 'lucide-react';
import { supabase } from '@/integrations/supabase/client';
import { useToast } from '@/components/ui/use-toast';
import { ScanResults } from './ScanResults';
import { Dialog, DialogContent, DialogHeader, DialogTitle } from '@/components/ui/dialog';
import { generateReport } from '@/services/scanService';

interface Scan {
  scan_id: string;
  target: string;
  profile: string | null;
  status: string | null;
  start_time: string | null;
  end_time: string | null;
  scan_depth: string | null;
}

export const ScanHistory = () => {
  const [searchTerm, setSearchTerm] = useState('');
  const [filterStatus, setFilterStatus] = useState('all');
  const [scans, setScans] = useState<Scan[]>([]);
  const [loading, setLoading] = useState(true);
  const [selectedScanId, setSelectedScanId] = useState<string | null>(null);
  const [selectedScans, setSelectedScans] = useState<Set<string>>(new Set());
  const [isGeneratingReport, setIsGeneratingReport] = useState<string | null>(null);
  const [isBulkGenerating, setIsBulkGenerating] = useState(false);
  const { toast } = useToast();

  useEffect(() => {
    fetchScans();
  }, []);

  const fetchScans = async () => {
    try {
      const { data, error } = await supabase
        .from('scans')
        .select('*')
        .order('start_time', { ascending: false });

      if (error) throw error;
      setScans(data || []);
    } catch (error) {
      console.error('Error fetching scans:', error);
      toast({
        title: "Error",
        description: "Failed to load scan history",
        variant: "destructive"
      });
    } finally {
      setLoading(false);
    }
  };

  const handleGenerateReport = async (scanId: string) => {
    setIsGeneratingReport(scanId);
    try {
      await generateReport(scanId);
      toast({
        title: "Report Generated",
        description: "AI-powered security report has been created successfully.",
      });
    } catch (error) {
      toast({
        title: "Report Generation Failed",
        description: error instanceof Error ? error.message : "Failed to generate report",
        variant: "destructive"
      });
    } finally {
      setIsGeneratingReport(null);
    }
  };

  const handleBulkGenerateReports = async () => {
    if (selectedScans.size === 0) return;

    setIsBulkGenerating(true);
    const scanIds = Array.from(selectedScans);
    let successCount = 0;
    let failCount = 0;

    for (const scanId of scanIds) {
      try {
        await generateReport(scanId);
        successCount++;
      } catch (error) {
        console.error(`Failed to generate report for scan ${scanId}:`, error);
        failCount++;
      }
    }

    setIsBulkGenerating(false);
    setSelectedScans(new Set());

    if (successCount > 0) {
      toast({
        title: "Bulk Report Generation Complete",
        description: `Successfully generated ${successCount} report${successCount > 1 ? 's' : ''}${failCount > 0 ? `. ${failCount} failed.` : '.'}`,
      });
    } else {
      toast({
        title: "Report Generation Failed",
        description: "Failed to generate any reports",
        variant: "destructive"
      });
    }
  };

  const toggleScanSelection = (scanId: string) => {
    const newSelection = new Set(selectedScans);
    if (newSelection.has(scanId)) {
      newSelection.delete(scanId);
    } else {
      newSelection.add(scanId);
    }
    setSelectedScans(newSelection);
  };

  const toggleSelectAll = () => {
    if (selectedScans.size === filteredScans.length) {
      setSelectedScans(new Set());
    } else {
      setSelectedScans(new Set(filteredScans.map(s => s.scan_id)));
    }
  };

  const getStatusBadge = (status: string) => {
    const variants = {
      completed: 'bg-green-100 text-green-800',
      running: 'bg-blue-100 text-blue-800',
      failed: 'bg-red-100 text-red-800',
      pending: 'bg-yellow-100 text-yellow-800',
    };
    return variants[status as keyof typeof variants] || 'bg-gray-100 text-gray-800';
  };

  const formatDuration = (startTime: string | null, endTime: string | null) => {
    if (!startTime || !endTime) return 'N/A';
    const start = new Date(startTime);
    const end = new Date(endTime);
    const diffMs = end.getTime() - start.getTime();
    const diffMins = Math.floor(diffMs / 60000);
    const diffSecs = Math.floor((diffMs % 60000) / 1000);
    return `${diffMins}m ${diffSecs}s`;
  };

  const filteredScans = scans.filter(scan => {
    const matchesSearch = scan.target.toLowerCase().includes(searchTerm.toLowerCase());
    const matchesStatus = filterStatus === 'all' || scan.status === filterStatus;
    return matchesSearch && matchesStatus;
  });

  if (loading) {
    return <div className="p-6">Loading scan history...</div>;
  }

  return (
    <div className="space-y-6">
      <div className="flex justify-between items-center">
        <div>
          <h1 className="text-3xl font-bold text-slate-900">Scan History</h1>
          <p className="text-slate-600 mt-1">View and manage your security scans</p>
        </div>
        {selectedScans.size > 0 && (
          <Button 
            onClick={handleBulkGenerateReports}
            disabled={isBulkGenerating}
            className="bg-blue-600 hover:bg-blue-700"
          >
            {isBulkGenerating ? (
              <>
                <Loader2 className="h-4 w-4 mr-2 animate-spin" />
                Generating {selectedScans.size} Report{selectedScans.size > 1 ? 's' : ''}...
              </>
            ) : (
              <>
                <FileText className="h-4 w-4 mr-2" />
                Generate {selectedScans.size} Report{selectedScans.size > 1 ? 's' : ''}
              </>
            )}
          </Button>
        )}
      </div>

      <Card>
        <CardHeader>
          <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between space-y-4 sm:space-y-0">
            <CardTitle>Recent Scans</CardTitle>
            <div className="flex flex-col sm:flex-row space-y-2 sm:space-y-0 sm:space-x-2">
              <div className="relative">
                <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 h-4 w-4 text-slate-400" />
                <Input
                  placeholder="Search targets..."
                  value={searchTerm}
                  onChange={(e) => setSearchTerm(e.target.value)}
                  className="pl-10 w-full sm:w-64"
                />
              </div>
              <Select value={filterStatus} onValueChange={setFilterStatus}>
                <SelectTrigger className="w-full sm:w-40">
                  <Filter className="h-4 w-4 mr-2" />
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="all">All Status</SelectItem>
                  <SelectItem value="completed">Completed</SelectItem>
                  <SelectItem value="running">Running</SelectItem>
                  <SelectItem value="failed">Failed</SelectItem>
                </SelectContent>
              </Select>
            </div>
          </div>
        </CardHeader>
        <CardContent>
          <div className="overflow-x-auto">
            <table className="w-full">
              <thead>
                <tr className="border-b border-slate-200">
                  <th className="text-left py-3 px-4 font-medium text-slate-600 w-12">
                    <Checkbox
                      checked={selectedScans.size === filteredScans.length && filteredScans.length > 0}
                      onCheckedChange={toggleSelectAll}
                      aria-label="Select all scans"
                    />
                  </th>
                  <th className="text-left py-3 px-4 font-medium text-slate-600">Target</th>
                  <th className="text-left py-3 px-4 font-medium text-slate-600">Profile</th>
                  <th className="text-left py-3 px-4 font-medium text-slate-600">Depth</th>
                  <th className="text-left py-3 px-4 font-medium text-slate-600">Status</th>
                  <th className="text-left py-3 px-4 font-medium text-slate-600">Date</th>
                  <th className="text-left py-3 px-4 font-medium text-slate-600">Duration</th>
                  <th className="text-left py-3 px-4 font-medium text-slate-600">Actions</th>
                </tr>
              </thead>
              <tbody>
                {filteredScans.map((scan) => (
                  <tr key={scan.scan_id} className="border-b border-slate-100 hover:bg-slate-50">
                    <td className="py-4 px-4">
                      <Checkbox
                        checked={selectedScans.has(scan.scan_id)}
                        onCheckedChange={() => toggleScanSelection(scan.scan_id)}
                        aria-label={`Select scan ${scan.target}`}
                      />
                    </td>
                    <td className="py-4 px-4">
                      <div className="font-medium text-slate-900">{scan.target}</div>
                    </td>
                    <td className="py-4 px-4 text-slate-600">{scan.profile || 'Unknown'}</td>
                    <td className="py-4 px-4 text-slate-600">{scan.scan_depth || 'N/A'}</td>
                    <td className="py-4 px-4">
                      <Badge className={getStatusBadge(scan.status || 'unknown')}>
                        {scan.status || 'unknown'}
                      </Badge>
                    </td>
                    <td className="py-4 px-4 text-slate-600">
                      {scan.start_time ? new Date(scan.start_time).toLocaleDateString() : 'N/A'}
                    </td>
                    <td className="py-4 px-4 text-slate-600">
                      {formatDuration(scan.start_time, scan.end_time)}
                    </td>
                    <td className="py-4 px-4">
                      <div className="flex space-x-2">
                        {scan.status === 'completed' && (
                          <Button 
                            size="sm" 
                            variant="outline"
                            onClick={() => setSelectedScanId(scan.scan_id)}
                          >
                            <Eye className="h-4 w-4 mr-1" />
                            View
                          </Button>
                        )}
                        <Button 
                          size="sm" 
                          variant="outline"
                          onClick={() => handleGenerateReport(scan.scan_id)}
                          disabled={isGeneratingReport === scan.scan_id}
                        >
                          <FileText className="h-4 w-4 mr-1" />
                          {isGeneratingReport === scan.scan_id ? 'Generating...' : 'Report'}
                        </Button>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </CardContent>
      </Card>

      <Dialog open={!!selectedScanId} onOpenChange={() => setSelectedScanId(null)}>
        <DialogContent className="max-w-6xl max-h-[90vh] overflow-y-auto">
          <DialogHeader>
            <DialogTitle>Scan Results</DialogTitle>
          </DialogHeader>
          {selectedScanId && <ScanResults scanId={selectedScanId} />}
        </DialogContent>
      </Dialog>
    </div>
  );
};
