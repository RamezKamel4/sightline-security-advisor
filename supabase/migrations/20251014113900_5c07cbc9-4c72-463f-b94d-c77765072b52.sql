-- Enable RLS on users table
ALTER TABLE public.users ENABLE ROW LEVEL SECURITY;

-- Policy: Users can view their own data
CREATE POLICY "Users can view own profile"
  ON public.users
  FOR SELECT
  USING (auth.uid() = user_id);

-- Policy: Users can update their own data
CREATE POLICY "Users can update own profile"
  ON public.users
  FOR UPDATE
  USING (auth.uid() = user_id)
  WITH CHECK (auth.uid() = user_id);

-- Enable RLS on cve table (public reference data)
ALTER TABLE public.cve ENABLE ROW LEVEL SECURITY;

-- Policy: All authenticated users can read CVE data
CREATE POLICY "Anyone can view CVE data"
  ON public.cve
  FOR SELECT
  USING (true);

-- Policy: Only service role can insert CVE data
CREATE POLICY "Service role can insert CVE data"
  ON public.cve
  FOR INSERT
  WITH CHECK (auth.role() = 'service_role');