-- Update the RLS policy to allow consultants to view reports assigned to them
DROP POLICY IF EXISTS "Consultants can view reports" ON public.reports;

CREATE POLICY "Consultants can view assigned reports" 
ON public.reports 
FOR SELECT 
USING (
  -- Admins can see all reports
  has_role(auth.uid(), 'admin')
  OR
  -- Consultants can see reports assigned to them
  (has_role(auth.uid(), 'consultant') AND consultant_id = auth.uid())
  OR
  -- Users can see their own scan reports that are approved
  (status = 'approved' AND EXISTS (
    SELECT 1 FROM scans 
    WHERE scans.scan_id = reports.scan_id 
    AND scans.user_id = auth.uid()
  ))
);