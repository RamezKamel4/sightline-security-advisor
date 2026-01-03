-- Allow consultants to view scans that have pending reports
CREATE POLICY "Consultants can view scans with pending reports"
ON public.scans
FOR SELECT
USING (
  has_role(auth.uid(), 'consultant'::app_role) AND 
  EXISTS (
    SELECT 1 FROM reports 
    WHERE reports.scan_id = scans.scan_id 
    AND reports.status = 'pending_review'
  )
);

-- Allow consultants to view user profiles for pending reports
CREATE POLICY "Consultants can view users for pending reports"
ON public.users
FOR SELECT
USING (
  has_role(auth.uid(), 'consultant'::app_role) AND 
  EXISTS (
    SELECT 1 FROM scans 
    JOIN reports ON reports.scan_id = scans.scan_id
    WHERE scans.user_id = users.user_id 
    AND reports.status = 'pending_review'
  )
);