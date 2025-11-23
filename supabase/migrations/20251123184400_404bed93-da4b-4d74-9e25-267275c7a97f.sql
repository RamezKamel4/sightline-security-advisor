-- Drop the existing restrictive policy for users viewing reports
DROP POLICY IF EXISTS "Users can view approved reports for their scans" ON public.reports;

-- Create a new policy that allows users to view ALL report metadata for their own scans
-- Users can see that a report exists and its status, but content viewing is still restricted elsewhere
CREATE POLICY "Users can view report metadata for their scans"
ON public.reports
FOR SELECT
USING (
  EXISTS (
    SELECT 1
    FROM scans
    WHERE scans.scan_id = reports.scan_id 
    AND scans.user_id = auth.uid()
  )
  OR has_role(auth.uid(), 'admin'::app_role)
  OR has_role(auth.uid(), 'consultant'::app_role)
);

-- Add a comment to explain the policy
COMMENT ON POLICY "Users can view report metadata for their scans" ON public.reports IS 
'Allows users to see report existence, status, and consultant assignment for their own scans. Content access is controlled by frontend logic based on status.';