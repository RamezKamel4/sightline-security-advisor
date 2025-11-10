
import React, { useState, useEffect } from 'react';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Input } from '@/components/ui/input';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import { Checkbox } from '@/components/ui/checkbox';
import { FileText, Download, Search, Filter, Eye, Loader2, UserCheck } from 'lucide-react';
import { supabase } from '@/integrations/supabase/client';
import { useToast } from '@/components/ui/use-toast';
import { ScanResults } from './ScanResults';
import { Dialog, DialogContent, DialogHeader, DialogTitle } from '@/components/ui/dialog';
import { generateReport } from '@/services/scanService';
import { useQuery } from '@tanstack/react-query';
import { 
  Pagination, 
  PaginationContent, 
  PaginationItem, 
  PaginationLink, 
  PaginationNext, 
  PaginationPrevious,
  PaginationEllipsis
} from '@/components/ui/pagination';

interface Scan {
  scan_id: string;
  target: string;
  profile: string | null;
  status: string | null;
  start_time: string | null;
  end_time: string | null;
  reports?: {
    report_id: string;
    consultant_id: string | null;
  }[];
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
  const [currentPage, setCurrentPage] = useState(1);
  const [itemsPerPage, setItemsPerPage] = useState(10);
  const { toast } = useToast();

  // Fetch all consultants and admins
  const { data: consultants } = useQuery({
    queryKey: ['consultants-and-admins'],
    queryFn: async () => {
      const { data: roleData, error: roleError } = await supabase
        .from('user_roles')
        .select('user_id')
        .in('role', ['consultant', 'admin']);
      
      if (roleError) throw roleError;
      if (!roleData || roleData.length === 0) return [];
      
      const userIds = [...new Set(roleData.map(r => r.user_id))];
      
      const { data: userData, error: userError } = await supabase
        .from('users')
        .select('user_id, email, name')
        .in('user_id', userIds);
      
      if (userError) throw userError;
      return userData || [];
    },
  });

  useEffect(() => {
    fetchScans();
  }, []);

  const fetchScans = async () => {
    try {
      const { data, error } = await supabase
        .from('scans')
        .select(`
          *,
          reports (
            report_id,
            consultant_id
          )
        `)
        .order('start_time', { ascending: false });

      if (error) throw error;
      setScans((data as any) || []);
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
    await fetchScans(); // Refresh to show new reports

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

  const handleConsultantChange = async (reportId: string, consultantId: string) => {
    try {
      const { error } = await supabase
        .from('reports')
        .update({ consultant_id: consultantId === 'none' ? null : consultantId })
        .eq('report_id', reportId);

      if (error) throw error;

      toast({
        title: "Consultant Updated",
        description: "Report consultant has been updated successfully.",
      });

      await fetchScans(); // Refresh the data
    } catch (error) {
      console.error('Error updating consultant:', error);
      toast({
        title: "Update Failed",
        description: "Failed to update consultant assignment.",
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
    if (selectedScans.size === paginatedScans.length && paginatedScans.length > 0) {
      const currentPageIds = new Set(paginatedScans.map(s => s.scan_id));
      const newSelection = new Set(selectedScans);
      currentPageIds.forEach(id => newSelection.delete(id));
      setSelectedScans(newSelection);
    } else {
      const newSelection = new Set(selectedScans);
      paginatedScans.forEach(scan => newSelection.add(scan.scan_id));
      setSelectedScans(newSelection);
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

  const totalPages = Math.ceil(filteredScans.length / itemsPerPage);
  const startIndex = (currentPage - 1) * itemsPerPage;
  const endIndex = startIndex + itemsPerPage;
  const paginatedScans = filteredScans.slice(startIndex, endIndex);

  useEffect(() => {
    setCurrentPage(1);
  }, [searchTerm, filterStatus, itemsPerPage]);

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
              <Select value={itemsPerPage.toString()} onValueChange={(val) => setItemsPerPage(Number(val))}>
                <SelectTrigger className="w-full sm:w-32">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="5">5 per page</SelectItem>
                  <SelectItem value="10">10 per page</SelectItem>
                  <SelectItem value="20">20 per page</SelectItem>
                  <SelectItem value="50">50 per page</SelectItem>
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
                      checked={paginatedScans.length > 0 && paginatedScans.every(scan => selectedScans.has(scan.scan_id))}
                      onCheckedChange={toggleSelectAll}
                      aria-label="Select all scans on this page"
                    />
                  </th>
                  <th className="text-left py-3 px-4 font-medium text-slate-600">Target</th>
                  <th className="text-left py-3 px-4 font-medium text-slate-600">Profile</th>
                  <th className="text-left py-3 px-4 font-medium text-slate-600">Status</th>
                  <th className="text-left py-3 px-4 font-medium text-slate-600">Date</th>
                  <th className="text-left py-3 px-4 font-medium text-slate-600">Duration</th>
                  <th className="text-left py-3 px-4 font-medium text-slate-600">Consultant</th>
                  <th className="text-left py-3 px-4 font-medium text-slate-600">Actions</th>
                </tr>
              </thead>
              <tbody>
                {paginatedScans.map((scan) => (
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
                      {scan.reports && scan.reports.length > 0 ? (
                        <Select 
                          value={scan.reports[0].consultant_id || 'none'} 
                          onValueChange={(value) => handleConsultantChange(scan.reports[0].report_id, value)}
                        >
                          <SelectTrigger className="w-[180px]">
                            <SelectValue placeholder="Select consultant" />
                          </SelectTrigger>
                          <SelectContent>
                            <SelectItem value="none">None</SelectItem>
                            {consultants?.map((consultant: any) => (
                              <SelectItem key={consultant.user_id} value={consultant.user_id}>
                                {consultant.name || consultant.email}
                              </SelectItem>
                            ))}
                          </SelectContent>
                        </Select>
                      ) : (
                        <span className="text-slate-400 text-sm flex items-center gap-1">
                          <UserCheck className="h-4 w-4" />
                          No report
                        </span>
                      )}
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
          {totalPages > 1 && (
            <div className="mt-4 flex items-center justify-between">
              <p className="text-sm text-slate-600">
                Showing {startIndex + 1} to {Math.min(endIndex, filteredScans.length)} of {filteredScans.length} results
              </p>
              <Pagination>
                <PaginationContent>
                  <PaginationItem>
                    <PaginationPrevious 
                      onClick={() => setCurrentPage(p => Math.max(1, p - 1))}
                      className={currentPage === 1 ? 'pointer-events-none opacity-50' : 'cursor-pointer'}
                    />
                  </PaginationItem>
                  {Array.from({ length: Math.min(5, totalPages) }, (_, i) => {
                    let pageNum;
                    if (totalPages <= 5) {
                      pageNum = i + 1;
                    } else if (currentPage <= 3) {
                      pageNum = i + 1;
                    } else if (currentPage >= totalPages - 2) {
                      pageNum = totalPages - 4 + i;
                    } else {
                      pageNum = currentPage - 2 + i;
                    }
                    return (
                      <PaginationItem key={pageNum}>
                        <PaginationLink
                          onClick={() => setCurrentPage(pageNum)}
                          isActive={currentPage === pageNum}
                          className="cursor-pointer"
                        >
                          {pageNum}
                        </PaginationLink>
                      </PaginationItem>
                    );
                  })}
                  {totalPages > 5 && currentPage < totalPages - 2 && (
                    <PaginationItem>
                      <PaginationEllipsis />
                    </PaginationItem>
                  )}
                  <PaginationItem>
                    <PaginationNext 
                      onClick={() => setCurrentPage(p => Math.min(totalPages, p + 1))}
                      className={currentPage === totalPages ? 'pointer-events-none opacity-50' : 'cursor-pointer'}
                    />
                  </PaginationItem>
                </PaginationContent>
              </Pagination>
            </div>
          )}
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
