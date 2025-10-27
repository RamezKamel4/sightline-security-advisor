-- Remove scan_depth from scans table
ALTER TABLE public.scans DROP COLUMN IF EXISTS scan_depth;

-- Remove scan_depth from scheduled_scans table
ALTER TABLE public.scheduled_scans DROP COLUMN IF EXISTS scan_depth;

-- Drop and recreate the get_due_scheduled_scans function without scan_depth
DROP FUNCTION IF EXISTS public.get_due_scheduled_scans();

CREATE OR REPLACE FUNCTION public.get_due_scheduled_scans()
RETURNS TABLE(
  id UUID,
  user_id UUID,
  target TEXT,
  profile TEXT,
  frequency TEXT,
  scheduled_time TIME
)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path TO 'public'
AS $$
BEGIN
  RETURN QUERY
  SELECT 
    s.id,
    s.user_id,
    s.target,
    s.profile,
    s.frequency,
    s.scheduled_time
  FROM public.scheduled_scans s
  WHERE s.is_active = true
    AND s.next_run_at <= now()
  ORDER BY s.next_run_at ASC;
END;
$$;