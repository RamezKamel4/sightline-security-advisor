import { useState } from 'react';
import { supabase } from '@/integrations/supabase/client';
import { useQuery } from '@tanstack/react-query';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Eye, CheckCircle } from 'lucide-react';
import { ReviewReportModal } from './ReviewReportModal';
import {
  Pagination,
  PaginationContent,
  PaginationItem,
  PaginationLink,
  PaginationNext,
  PaginationPrevious,
} from '@/components/ui/pagination';

interface PendingReport {
  report_id: string;
  scan_id: string;
  created_at: string;
  summary: string;
  pdf_url: string | null;
  scans: {
    scan_id: string;
    target: string;
    start_time: string;
    user_id: string;
    users: {
      user_id: string;
      name: string;
      email: string;
    };
  };
}

export const PendingReports = () => {
  const [selectedReport, setSelectedReport] = useState<PendingReport | null>(null);
  const [currentPage, setCurrentPage] = useState(1);
  const reportsPerPage = 5;

  const { data: reports, isLoading, refetch } = useQuery({
    queryKey: ['pending-reports'],
    queryFn: async () => {
      const { data, error } = await supabase.functions.invoke('get-pending-reports');
      
      if (error) throw error;
      return data.reports as PendingReport[];
    },
  });

  const handleOpenModal = (report: PendingReport) => {
    setSelectedReport(report);
  };

  const handleCloseModal = () => {
    setSelectedReport(null);
  };

  const handleSuccess = () => {
    refetch();
    handleCloseModal();
  };

  if (isLoading) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-primary"></div>
      </div>
    );
  }

  const totalPages = Math.ceil((reports?.length || 0) / reportsPerPage);
  const startIndex = (currentPage - 1) * reportsPerPage;
  const endIndex = startIndex + reportsPerPage;
  const paginatedReports = reports?.slice(startIndex, endIndex);

  return (
    <div className="space-y-6">
      <div>
        <h2 className="text-3xl font-bold text-foreground">Pending Reports</h2>
        <p className="text-muted-foreground mt-2">
          Review and approve AI-generated security reports before they're visible to clients
        </p>
      </div>

      {!reports || reports.length === 0 ? (
        <Card>
          <CardContent className="pt-6">
            <div className="text-center py-12">
              <CheckCircle className="h-12 w-12 text-green-500 mx-auto mb-4" />
              <p className="text-lg text-muted-foreground">
                No pending reports to review
              </p>
            </div>
          </CardContent>
        </Card>
      ) : (
        <>
          <div className="grid gap-4">
            {paginatedReports?.map((report) => (
            <Card key={report.report_id} className="border-border">
              <CardHeader>
                <div className="flex items-start justify-between">
                  <div className="space-y-1 flex-1">
                    <CardTitle className="text-xl">
                      Report for {report.scans.target}
                    </CardTitle>
                    <CardDescription>
                      <div className="space-y-1">
                        <p><strong>Client:</strong> {report.scans.users.name} ({report.scans.users.email})</p>
                        <p><strong>Scan Date:</strong> {new Date(report.scans.start_time).toLocaleString()}</p>
                        <p><strong>Generated:</strong> {new Date(report.created_at).toLocaleString()}</p>
                      </div>
                    </CardDescription>
                  </div>
                  <Badge variant="secondary" className="ml-4">
                    Pending Review
                  </Badge>
                </div>
              </CardHeader>
              <CardContent>
                <Button
                  variant="outline"
                  size="sm"
                  onClick={() => handleOpenModal(report)}
                  className="gap-2"
                >
                  <Eye className="h-4 w-4" />
                  View Report
                </Button>
              </CardContent>
            </Card>
            ))}
          </div>

          {totalPages > 1 && (
            <Pagination className="mt-6">
              <PaginationContent>
                <PaginationItem>
                  <PaginationPrevious
                    onClick={() => setCurrentPage(p => Math.max(1, p - 1))}
                    className={currentPage === 1 ? 'pointer-events-none opacity-50' : 'cursor-pointer'}
                  />
                </PaginationItem>
                {Array.from({ length: totalPages }, (_, i) => i + 1).map((page) => (
                  <PaginationItem key={page}>
                    <PaginationLink
                      onClick={() => setCurrentPage(page)}
                      isActive={currentPage === page}
                      className="cursor-pointer"
                    >
                      {page}
                    </PaginationLink>
                  </PaginationItem>
                ))}
                <PaginationItem>
                  <PaginationNext
                    onClick={() => setCurrentPage(p => Math.min(totalPages, p + 1))}
                    className={currentPage === totalPages ? 'pointer-events-none opacity-50' : 'cursor-pointer'}
                  />
                </PaginationItem>
              </PaginationContent>
            </Pagination>
          )}
        </>
      )}

      {selectedReport && (
        <ReviewReportModal
          report={selectedReport}
          onClose={handleCloseModal}
          onSuccess={handleSuccess}
        />
      )}
    </div>
  );
};
