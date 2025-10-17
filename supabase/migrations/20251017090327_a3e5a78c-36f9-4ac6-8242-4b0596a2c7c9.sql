-- Allow authenticated users to insert CVE records
CREATE POLICY "Allow authenticated users to insert CVE records"
ON public.cve
FOR INSERT
TO authenticated
WITH CHECK (true);

-- Allow authenticated users to update CVE records
CREATE POLICY "Allow authenticated users to update CVE records"
ON public.cve
FOR UPDATE
TO authenticated
USING (true)
WITH CHECK (true);

-- Allow authenticated users to select CVE records
CREATE POLICY "Allow authenticated users to select CVE records"
ON public.cve
FOR SELECT
TO authenticated
USING (true);