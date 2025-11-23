import { useState } from 'react';
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from '@/components/ui/dialog';
import { Button } from '@/components/ui/button';
import { Textarea } from '@/components/ui/textarea';
import { Label } from '@/components/ui/label';
import { supabase } from '@/integrations/supabase/client';
import { toast } from 'sonner';
import { CheckCircle, XCircle } from 'lucide-react';

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
  action: 'approve' | 'reject';
  onClose: () => void;
  onSuccess: () => void;
}

export const ReviewReportModal = ({ report, action, onClose, onSuccess }: ReviewReportModalProps) => {
  const [notes, setNotes] = useState('');
  const [isSubmitting, setIsSubmitting] = useState(false);

  const handleSubmit = async () => {
    if (action === 'reject' && !notes.trim()) {
      toast.error('Please provide feedback for rejection');
      return;
    }

    setIsSubmitting(true);
    try {
      const functionName = action === 'approve' ? 'approve-report' : 'reject-report';
      const payload = action === 'approve' 
        ? { reportId: report.report_id }
        : { reportId: report.report_id, notes };

      const { error } = await supabase.functions.invoke(functionName, {
        body: payload,
      });

      if (error) throw error;

      if (action === 'approve') {
        toast.success('Report approved successfully');
      } else {
        toast.success('Report rejected - new version is being generated automatically');
      }
      onSuccess();
    } catch (error) {
      console.error(`Error ${action}ing report:`, error);
      toast.error(`Failed to ${action} report`);
    } finally {
      setIsSubmitting(false);
    }
  };

  return (
    <Dialog open={true} onOpenChange={onClose}>
      <DialogContent className="max-w-4xl max-h-[80vh] overflow-y-auto">
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2">
            {action === 'approve' ? (
              <>
                <CheckCircle className="h-5 w-5 text-green-600" />
                Review & Approve Report
              </>
            ) : (
              <>
                <XCircle className="h-5 w-5 text-red-600" />
                Reject Report
              </>
            )}
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
              <Button
                variant="outline"
                onClick={() => window.open(report.pdf_url!, '_blank')}
                className="w-full"
              >
                View PDF Report
              </Button>
            </div>
          )}

          {action === 'reject' && (
            <div className="space-y-2">
              <Label htmlFor="rejection-notes">
                Rejection Feedback <span className="text-red-600">*</span>
              </Label>
              <Textarea
                id="rejection-notes"
                value={notes}
                onChange={(e) => setNotes(e.target.value)}
                placeholder="Provide detailed feedback on why this report is being rejected..."
                rows={4}
                className="resize-none"
              />
              <p className="text-sm text-muted-foreground">
                This feedback will be used to improve future reports
              </p>
            </div>
          )}

          {action === 'approve' && (
            <div className="bg-green-50 dark:bg-green-950 p-4 rounded-lg border border-green-200 dark:border-green-800">
              <p className="text-sm text-green-800 dark:text-green-200">
                ✓ Once approved, this report will become visible to the client and they will receive a notification.
              </p>
            </div>
          )}
        </div>

        <DialogFooter>
          <Button variant="outline" onClick={onClose} disabled={isSubmitting}>
            Cancel
          </Button>
          <Button
            onClick={handleSubmit}
            disabled={isSubmitting || (action === 'reject' && !notes.trim())}
            variant={action === 'approve' ? 'default' : 'destructive'}
          >
            {isSubmitting ? (
              'Processing...'
            ) : (
              action === 'approve' ? 'Approve Report' : 'Reject Report'
            )}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
};
