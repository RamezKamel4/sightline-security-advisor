-- Create the update_updated_at_column function first
CREATE OR REPLACE FUNCTION public.update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
  NEW.updated_at = now();
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- Create scheduled_scans table to store recurring scan configurations
CREATE TABLE IF NOT EXISTS public.scheduled_scans (
  id UUID NOT NULL DEFAULT gen_random_uuid() PRIMARY KEY,
  user_id UUID NOT NULL,
  target TEXT NOT NULL,
  profile TEXT NOT NULL,
  scan_depth TEXT NOT NULL DEFAULT 'fast',
  frequency TEXT NOT NULL CHECK (frequency IN ('daily', 'weekly', 'monthly')),
  scheduled_time TIME NOT NULL,
  last_run_at TIMESTAMP WITH TIME ZONE,
  next_run_at TIMESTAMP WITH TIME ZONE NOT NULL,
  is_active BOOLEAN NOT NULL DEFAULT true,
  created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now(),
  updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now()
);

-- Enable RLS
ALTER TABLE public.scheduled_scans ENABLE ROW LEVEL SECURITY;

-- Create policies for scheduled scans
CREATE POLICY "Users can view their own scheduled scans"
ON public.scheduled_scans
FOR SELECT
USING (auth.uid() = user_id);

CREATE POLICY "Users can create their own scheduled scans"
ON public.scheduled_scans
FOR INSERT
WITH CHECK (auth.uid() = user_id);

CREATE POLICY "Users can update their own scheduled scans"
ON public.scheduled_scans
FOR UPDATE
USING (auth.uid() = user_id);

CREATE POLICY "Users can delete their own scheduled scans"
ON public.scheduled_scans
FOR DELETE
USING (auth.uid() = user_id);

-- Create index for efficient querying of due scans
CREATE INDEX idx_scheduled_scans_next_run ON public.scheduled_scans(next_run_at) WHERE is_active = true;

-- Create function to calculate next run time
CREATE OR REPLACE FUNCTION public.calculate_next_run(
  current_run TIMESTAMP WITH TIME ZONE,
  freq TEXT
) RETURNS TIMESTAMP WITH TIME ZONE AS $$
BEGIN
  CASE freq
    WHEN 'daily' THEN
      RETURN current_run + INTERVAL '1 day';
    WHEN 'weekly' THEN
      RETURN current_run + INTERVAL '7 days';
    WHEN 'monthly' THEN
      RETURN current_run + INTERVAL '1 month';
    ELSE
      RETURN current_run + INTERVAL '1 day';
  END CASE;
END;
$$ LANGUAGE plpgsql IMMUTABLE;

-- Create trigger to update updated_at
CREATE TRIGGER update_scheduled_scans_updated_at
BEFORE UPDATE ON public.scheduled_scans
FOR EACH ROW
EXECUTE FUNCTION public.update_updated_at_column();

-- Enable pg_cron extension
CREATE EXTENSION IF NOT EXISTS pg_cron;

-- Create a function that returns due scans
CREATE OR REPLACE FUNCTION public.get_due_scheduled_scans()
RETURNS TABLE (
  id UUID,
  user_id UUID,
  target TEXT,
  profile TEXT,
  scan_depth TEXT,
  frequency TEXT,
  scheduled_time TIME
) AS $$
BEGIN
  RETURN QUERY
  SELECT 
    s.id,
    s.user_id,
    s.target,
    s.profile,
    s.scan_depth,
    s.frequency,
    s.scheduled_time
  FROM public.scheduled_scans s
  WHERE s.is_active = true
    AND s.next_run_at <= now()
  ORDER BY s.next_run_at ASC;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- Schedule the edge function to run every minute
SELECT cron.schedule(
  'run-scheduled-scans',
  '* * * * *',
  $$
  SELECT
    net.http_post(
      url := 'https://bliwnrikjfzcialoznur.supabase.co/functions/v1/run-scheduled-scans',
      headers := '{"Content-Type": "application/json", "Authorization": "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6ImJsaXducmlramZ6Y2lhbG96bnVyIiwicm9sZSI6ImFub24iLCJpYXQiOjE3NDk1MDkwNDYsImV4cCI6MjA2NTA4NTA0Nn0.KVx5uaBmj5_IESBMgB7H72tWCBKWuj2-IU-9HpunCC4"}'::jsonb
    ) as request_id;
  $$
);