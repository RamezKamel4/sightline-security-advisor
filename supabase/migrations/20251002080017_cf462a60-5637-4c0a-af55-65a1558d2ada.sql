-- Create storage bucket for security reports
INSERT INTO storage.buckets (id, name, public, file_size_limit, allowed_mime_types)
VALUES (
  'reports',
  'reports',
  true,
  10485760, -- 10MB limit
  ARRAY['application/pdf']
);

-- Create storage policy for report uploads (service role only)
CREATE POLICY "Service role can upload reports"
ON storage.objects
FOR INSERT
TO service_role
WITH CHECK (bucket_id = 'reports');

-- Create storage policy for users to view their own reports
CREATE POLICY "Users can view reports for their scans"
ON storage.objects
FOR SELECT
USING (
  bucket_id = 'reports' AND
  EXISTS (
    SELECT 1
    FROM scans
    WHERE scans.scan_id = (storage.foldername(name))[1]
    AND scans.user_id = auth.uid()
  )
);

-- Allow public access to reports bucket for authenticated users
CREATE POLICY "Public reports access"
ON storage.objects
FOR SELECT
USING (bucket_id = 'reports');