-- Add UPDATE policy for findings table to allow CVE enrichment
CREATE POLICY "Users can update findings for their scans"
ON public.findings
FOR UPDATE
USING (
  EXISTS (
    SELECT 1 FROM public.scans
    WHERE scans.scan_id = findings.scan_id
    AND scans.user_id = auth.uid()
  )
)
WITH CHECK (
  EXISTS (
    SELECT 1 FROM public.scans
    WHERE scans.scan_id = findings.scan_id
    AND scans.user_id = auth.uid()
  )
);