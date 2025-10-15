-- Add host and state columns to findings table
ALTER TABLE public.findings 
ADD COLUMN IF NOT EXISTS host text,
ADD COLUMN IF NOT EXISTS state text;

-- Add index on host for better query performance
CREATE INDEX IF NOT EXISTS idx_findings_host ON public.findings(host);

COMMENT ON COLUMN public.findings.host IS 'IP address of the host where the finding was discovered';
COMMENT ON COLUMN public.findings.state IS 'Port state: open, filtered, closed, etc.';