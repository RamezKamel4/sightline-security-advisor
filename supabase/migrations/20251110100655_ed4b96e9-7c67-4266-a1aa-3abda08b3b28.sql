-- Create report status enum
CREATE TYPE public.report_status AS ENUM ('pending_review', 'approved', 'rejected');

-- Add new columns to reports table
ALTER TABLE public.reports
ADD COLUMN status public.report_status NOT NULL DEFAULT 'pending_review',
ADD COLUMN consultant_id uuid REFERENCES auth.users(id),
ADD COLUMN review_notes text,
ADD COLUMN reviewed_at timestamp with time zone;

-- Add consultant_id to users table to link clients to their assigned consultant
ALTER TABLE public.users
ADD COLUMN consultant_id uuid REFERENCES auth.users(id);

-- Create report audit log table
CREATE TABLE public.report_audit_log (
  id uuid NOT NULL DEFAULT gen_random_uuid() PRIMARY KEY,
  report_id uuid NOT NULL REFERENCES public.reports(report_id) ON DELETE CASCADE,
  action text NOT NULL,
  performed_by uuid NOT NULL REFERENCES auth.users(id),
  timestamp timestamp with time zone NOT NULL DEFAULT now(),
  notes text
);

-- Enable RLS on audit log
ALTER TABLE public.report_audit_log ENABLE ROW LEVEL SECURITY;

-- RLS policies for audit log
CREATE POLICY "Admins and consultants can view audit logs"
ON public.report_audit_log
FOR SELECT
USING (
  has_role(auth.uid(), 'admin'::app_role) 
  OR has_role(auth.uid(), 'consultant'::app_role)
);

CREATE POLICY "System can insert audit logs"
ON public.report_audit_log
FOR INSERT
WITH CHECK (true);

-- Update reports RLS policies to restrict client access to approved reports only
DROP POLICY IF EXISTS "Users can view reports for their scans" ON public.reports;

CREATE POLICY "Users can view approved reports for their scans"
ON public.reports
FOR SELECT
USING (
  (status = 'approved' AND EXISTS (
    SELECT 1 FROM scans 
    WHERE scans.scan_id = reports.scan_id 
    AND scans.user_id = auth.uid()
  ))
  OR has_role(auth.uid(), 'admin'::app_role)
  OR has_role(auth.uid(), 'consultant'::app_role)
);

-- Consultants can update reports (for approval/rejection)
CREATE POLICY "Consultants can update reports"
ON public.reports
FOR UPDATE
USING (has_role(auth.uid(), 'consultant'::app_role) OR has_role(auth.uid(), 'admin'::app_role))
WITH CHECK (has_role(auth.uid(), 'consultant'::app_role) OR has_role(auth.uid(), 'admin'::app_role));

-- Add index for faster consultant queries
CREATE INDEX idx_reports_status ON public.reports(status);
CREATE INDEX idx_reports_consultant ON public.reports(consultant_id);
CREATE INDEX idx_users_consultant ON public.users(consultant_id);