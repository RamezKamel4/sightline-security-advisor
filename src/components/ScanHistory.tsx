
import React, { useState, useEffect } from 'react';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Input } from '@/components/ui/input';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import { Checkbox } from '@/components/ui/checkbox';
import { FileText, Download, Search, Filter, Eye, Loader2, UserCheck, CheckCircle, XCircle } from 'lucide-react';
import { supabase } from '@/integrations/supabase/client';
import { useToast } from '@/components/ui/use-toast';
import { useAuth } from '@/contexts/AuthContext';
import { ScanResults } from './ScanResults';
import { Dialog, DialogContent, DialogHeader, DialogTitle } from '@/components/ui/dialog';
import { Tooltip, TooltipContent, TooltipProvider, TooltipTrigger } from '@/components/ui/tooltip';
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
  report?: {
    report_id: string;
    consultant_id: string | null;
    status: string;
    review_notes?: string | null;
  } | null;
}

export const ScanHistory = () => {
  const [searchTerm, setSearchTerm] = useState('');
  const [filterStatus, setFilterStatus] = useState('all');
  const [filterConsultationStatus, setFilterConsultationStatus] = useState('all');
  const [scans, setScans] = useState<Scan[]>([]);
  const [loading, setLoading] = useState(true);
  const [selectedScanId, setSelectedScanId] = useState<string | null>(null);
  const [selectedScans, setSelectedScans] = useState<Set<string>>(new Set());
  const [isGeneratingReport, setIsGeneratingReport] = useState<string | null>(null);
  const [isBulkGenerating, setIsBulkGenerating] = useState(false);
  const [currentPage, setCurrentPage] = useState(1);
  const [itemsPerPage, setItemsPerPage] = useState(10);
  const { toast } = useToast();
  const { user } = useAuth();

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
  }, [user]);
 
  const fetchScans = async () => {
    try {
      console.log('🔍 Fetching scans with latest reports...');
      
      if (!user) {
        console.warn('❌ No authenticated user found when fetching scans');
        setScans([]);
        setLoading(false);
        return;
      }
      
      console.log('🔐 Current user ID:', user.id);
      console.log('🔐 Current user email:', user.email);
      
      // Get scans for current user only (admins see only their own scans)
      const { data: scansData, error: scansError } = await supabase
        .from('scans')
        .select('*')
        .eq('user_id', user.id)
        .order('start_time', { ascending: false });
 
      if (scansError) {
        console.error('❌ Error fetching scans:', scansError);
        throw scansError;
      }
 
      const rawScans = scansData || [];
      console.log('📊 Scans returned from DB (before user filter):', rawScans.length);
      console.log('📋 First raw scan sample:', rawScans[0]);
 
      // Extra safety: also filter by user_id on the client, so admins never see other users' scans
      const userScans = rawScans.filter((scan: any) => scan.user_id === user.id);
      console.log('📊 Scans after filtering by current user_id:', userScans.length);
      console.log('📋 First user scan sample:', userScans[0]);
 
      // Then, for each scan, get the latest report
      const scansWithLatestReports = await Promise.all(
        userScans.map(async (scan) => {
          const { data: reportData } = await supabase
            .from('reports')
            .select('report_id, consultant_id, status, review_notes')
            .eq('scan_id', scan.scan_id)
            .order('created_at', { ascending: false })
            .limit(1)
            .maybeSingle();
 
          return {
            ...scan,
            report: reportData
          };
        })
      );
      
      console.log('✅ Fetched scans with latest reports:', scansWithLatestReports.length);
      console.log('📊 Sample scan with latest report:', scansWithLatestReports[0]);
      
      setScans(scansWithLatestReports as any);
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
      await fetchScans(); // Refresh to show new report
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

  const getConsultationStatusBadge = (scan: Scan) => {
    if (!scan.report) {
      return <span className="text-slate-400 text-sm">No report</span>;
    }

    const reportStatus = scan.report.status;
    const reviewNotes = scan.report.review_notes;

    switch (reportStatus) {
      case 'approved':
        return (
          <Badge className="bg-green-100 text-green-800">
            Approved
          </Badge>
        );
      case 'rejected':
        if (reviewNotes) {
          return (
            <TooltipProvider>
              <Tooltip>
                <TooltipTrigger asChild>
                  <Badge className="bg-red-100 text-red-800 cursor-help">
                    Rejected
                  </Badge>
                </TooltipTrigger>
                <TooltipContent className="max-w-xs">
                  <p className="text-sm font-semibold mb-1">Review Notes:</p>
                  <p className="text-sm">{reviewNotes}</p>
                </TooltipContent>
              </Tooltip>
            </TooltipProvider>
          );
        }
        return (
          <Badge className="bg-red-100 text-red-800">
            Rejected
          </Badge>
        );
      case 'pending_review':
        return (
          <Badge className="bg-yellow-100 text-yellow-800">
            Pending
          </Badge>
        );
      default:
        return (
          <span className="text-slate-400 text-sm">-</span>
        );
    }
  };

  const getConsultantName = (consultantId: string | null) => {
    if (!consultantId) return 'Not assigned';
    const consultant = consultants?.find((c: any) => c.user_id === consultantId);
    return consultant ? (consultant.name || consultant.email) : 'Unknown';
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
    const report = scan.report;
    
    let matchesConsultation = true;
    if (filterConsultationStatus !== 'all') {
      const hasReport = !!report;
      if (filterConsultationStatus === 'no_report') {
        matchesConsultation = !hasReport;
      } else {
        matchesConsultation = hasReport && report?.status === filterConsultationStatus;
      }
    }
    
    return matchesSearch && matchesStatus && matchesConsultation;
  });

  const totalPages = Math.ceil(filteredScans.length / itemsPerPage);
  const startIndex = (currentPage - 1) * itemsPerPage;
  const endIndex = startIndex + itemsPerPage;
  const paginatedScans = filteredScans.slice(startIndex, endIndex);

  useEffect(() => {
    setCurrentPage(1);
  }, [searchTerm, filterStatus, filterConsultationStatus, itemsPerPage]);

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
        <div className="flex gap-2">
          <Button 
            variant="outline" 
            onClick={() => {
              setLoading(true);
              fetchScans();
            }}
            size="sm"
          >
            Refresh
          </Button>
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
              <Select value={filterConsultationStatus} onValueChange={setFilterConsultationStatus}>
                <SelectTrigger className="w-full sm:w-44">
                  <Filter className="h-4 w-4 mr-2" />
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="all">All Consultations</SelectItem>
                  <SelectItem value="approved">Approved</SelectItem>
                  <SelectItem value="rejected">Rejected</SelectItem>
                  <SelectItem value="pending_review">Pending</SelectItem>
                  <SelectItem value="no_report">No Report</SelectItem>
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
                  <th className="text-left py-3 px-4 font-medium text-slate-600">Consultation</th>
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
                      {getConsultationStatusBadge(scan)}
                    </td>
                    <td className="py-4 px-4">
                      {scan.report ? (
                        <div className="flex items-center gap-2">
                          <UserCheck className="h-4 w-4 text-slate-400" />
                          <span className="text-slate-700">
                            {getConsultantName(scan.report.consultant_id)}
                          </span>
                        </div>
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
                          isActive={pageNum === currentPage}
                          onClick={() => setCurrentPage(pageNum)}
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
