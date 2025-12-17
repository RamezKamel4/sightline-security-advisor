import { useState } from 'react';
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from '@/components/ui/dialog';
import { AlertDialog, AlertDialogAction, AlertDialogCancel, AlertDialogContent, AlertDialogDescription, AlertDialogFooter, AlertDialogHeader, AlertDialogTitle } from '@/components/ui/alert-dialog';
import { Button } from '@/components/ui/button';
import { Textarea } from '@/components/ui/textarea';
import { Label } from '@/components/ui/label';
import { supabase } from '@/integrations/supabase/client';
import { toast } from 'sonner';
import { CheckCircle, XCircle, FileText, Download } from 'lucide-react';

interface ReviewReportModalProps {
  report: {
    report_id: string;
    scan_id: string;
    summary: string;
    pdf_url: string | null;
    scans: {
      target: string;
      users: {
        name: string;
        email: string;
      };
    };
  };
  onClose: () => void;
  onSuccess: () => void;
}

export const ReviewReportModal = ({ report, onClose, onSuccess }: ReviewReportModalProps) => {
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [showApproveConfirm, setShowApproveConfirm] = useState(false);
  const [showRejectConfirm, setShowRejectConfirm] = useState(false);
  const [rejectionNotes, setRejectionNotes] = useState('');

  const handleApprove = async () => {
    setIsSubmitting(true);
    try {
      const { error } = await supabase.functions.invoke('approve-report', {
        body: { reportId: report.report_id },
      });

      if (error) throw error;

      toast.success('Report approved successfully');
      onSuccess();
    } catch (error) {
      console.error('Error approving report:', error);
      toast.error('Failed to approve report');
    } finally {
      setIsSubmitting(false);
      setShowApproveConfirm(false);
    }
  };

  const handleReject = async () => {
    if (!rejectionNotes.trim()) {
      toast.error('Please provide feedback for rejection');
      return;
    }

    setIsSubmitting(true);
    try {
      const { error } = await supabase.functions.invoke('reject-report', {
        body: { reportId: report.report_id, notes: rejectionNotes },
      });

      if (error) throw error;

      toast.success('Report rejected - new version is being generated automatically');
      onSuccess();
    } catch (error) {
      console.error('Error rejecting report:', error);
      toast.error('Failed to reject report');
    } finally {
      setIsSubmitting(false);
      setShowRejectConfirm(false);
    }
  };

  return (
    <>
      <Dialog open={true} onOpenChange={onClose}>
        <DialogContent className="max-w-4xl max-h-[85vh] overflow-y-auto">
          <DialogHeader>
            <DialogTitle className="flex items-center gap-2">
              <FileText className="h-5 w-5 text-primary" />
              Review Report
            </DialogTitle>
            <DialogDescription>
              Target: {report.scans.target} | Client: {report.scans.users.name} ({report.scans.users.email})
            </DialogDescription>
          </DialogHeader>

          <div className="space-y-4">
            <div>
              <h3 className="font-semibold text-lg mb-2">Report Content:</h3>
              <div className="bg-muted p-4 rounded-lg max-h-96 overflow-y-auto">
                <pre className="whitespace-pre-wrap text-sm font-mono">{report.summary}</pre>
              </div>
            </div>

            {report.pdf_url && (
              <div>
                <a
                  href={report.pdf_url}
                  target="_blank"
                  rel="noopener noreferrer"
                  download
                  className="w-full"
                >
                  <Button
                    variant="outline"
                    className="w-full gap-2"
                    type="button"
                  >
                    <Download className="h-4 w-4" />
                    Download PDF Report
                  </Button>
                </a>
              </div>
            )}
          </div>

          <DialogFooter className="flex flex-col sm:flex-row gap-2 pt-4 border-t">
            <Button variant="outline" onClick={onClose} disabled={isSubmitting}>
              Cancel
            </Button>
            <Button
              variant="destructive"
              onClick={() => setShowRejectConfirm(true)}
              disabled={isSubmitting}
              className="gap-2"
            >
              <XCircle className="h-4 w-4" />
              Reject
            </Button>
            <Button
              onClick={() => setShowApproveConfirm(true)}
              disabled={isSubmitting}
              className="gap-2"
            >
              <CheckCircle className="h-4 w-4" />
              Approve
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* Approve Confirmation Dialog */}
      <AlertDialog open={showApproveConfirm} onOpenChange={setShowApproveConfirm}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle className="flex items-center gap-2">
              <CheckCircle className="h-5 w-5 text-green-600" />
              Confirm Approval
            </AlertDialogTitle>
            <AlertDialogDescription>
              Are you sure you want to approve this report? Once approved, it will be visible to the client and they will receive a notification.
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel disabled={isSubmitting}>Cancel</AlertDialogCancel>
            <AlertDialogAction onClick={handleApprove} disabled={isSubmitting}>
              {isSubmitting ? 'Approving...' : 'Yes, Approve'}
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>

      {/* Reject Confirmation Dialog */}
      <AlertDialog open={showRejectConfirm} onOpenChange={setShowRejectConfirm}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle className="flex items-center gap-2">
              <XCircle className="h-5 w-5 text-red-600" />
              Confirm Rejection
            </AlertDialogTitle>
            <AlertDialogDescription>
              Are you sure you want to reject this report? A new version will be generated automatically based on your feedback.
            </AlertDialogDescription>
          </AlertDialogHeader>
          <div className="space-y-2 py-4">
            <Label htmlFor="rejection-notes">
              Rejection Feedback <span className="text-destructive">*</span>
            </Label>
            <Textarea
              id="rejection-notes"
              value={rejectionNotes}
              onChange={(e) => setRejectionNotes(e.target.value)}
              placeholder="Provide detailed feedback on why this report is being rejected..."
              rows={4}
              className="resize-none"
            />
            <p className="text-sm text-muted-foreground">
              This feedback will be used to improve the next version of the report.
            </p>
          </div>
          <AlertDialogFooter>
            <AlertDialogCancel disabled={isSubmitting}>Cancel</AlertDialogCancel>
            <AlertDialogAction 
              onClick={handleReject} 
              disabled={isSubmitting || !rejectionNotes.trim()}
              className="bg-destructive text-destructive-foreground hover:bg-destructive/90"
            >
              {isSubmitting ? 'Rejecting...' : 'Confirm Rejection'}
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </>
  );
};
