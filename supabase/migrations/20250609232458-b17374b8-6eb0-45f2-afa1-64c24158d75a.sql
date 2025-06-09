
-- Fix the scans table to auto-generate UUIDs and reference auth.users properly
ALTER TABLE public.scans 
ALTER COLUMN scan_id SET DEFAULT gen_random_uuid()::text;

-- Fix the findings table to auto-generate UUIDs
ALTER TABLE public.findings 
ALTER COLUMN finding_id SET DEFAULT gen_random_uuid()::text;

-- The reports table already has UUID generation, but let's ensure it's properly set
ALTER TABLE public.reports 
ALTER COLUMN report_id SET DEFAULT gen_random_uuid();

-- Add RLS policies for scans table so users can only see their own scans
ALTER TABLE public.scans ENABLE ROW LEVEL SECURITY;

CREATE POLICY "Users can view their own scans" 
  ON public.scans 
  FOR SELECT 
  USING (auth.uid() = user_id);

CREATE POLICY "Users can create their own scans" 
  ON public.scans 
  FOR INSERT 
  WITH CHECK (auth.uid() = user_id);

CREATE POLICY "Users can update their own scans" 
  ON public.scans 
  FOR UPDATE 
  USING (auth.uid() = user_id);

CREATE POLICY "Users can delete their own scans" 
  ON public.scans 
  FOR DELETE 
  USING (auth.uid() = user_id);

-- Add RLS policies for findings table (linked to scans)
ALTER TABLE public.findings ENABLE ROW LEVEL SECURITY;

CREATE POLICY "Users can view findings for their scans" 
  ON public.findings 
  FOR SELECT 
  USING (EXISTS (
    SELECT 1 FROM public.scans 
    WHERE scans.scan_id = findings.scan_id 
    AND scans.user_id = auth.uid()
  ));

CREATE POLICY "Users can create findings for their scans" 
  ON public.findings 
  FOR INSERT 
  WITH CHECK (EXISTS (
    SELECT 1 FROM public.scans 
    WHERE scans.scan_id = findings.scan_id 
    AND scans.user_id = auth.uid()
  ));

-- Add RLS policies for reports table (linked to scans)
ALTER TABLE public.reports ENABLE ROW LEVEL SECURITY;

CREATE POLICY "Users can view reports for their scans" 
  ON public.reports 
  FOR SELECT 
  USING (EXISTS (
    SELECT 1 FROM public.scans 
    WHERE scans.scan_id = reports.scan_id 
    AND scans.user_id = auth.uid()
  ));

CREATE POLICY "Users can create reports for their scans" 
  ON public.reports 
  FOR INSERT 
  WITH CHECK (EXISTS (
    SELECT 1 FROM public.scans 
    WHERE scans.scan_id = reports.scan_id 
    AND scans.user_id = auth.uid()
  ));
