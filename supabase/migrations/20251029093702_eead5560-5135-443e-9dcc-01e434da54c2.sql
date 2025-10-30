-- Add columns for storing original user input and normalized target
ALTER TABLE public.scans 
  ADD COLUMN user_input_target text,
  ADD COLUMN normalized_target text,
  ADD COLUMN estimated_hosts integer;

-- Migrate existing data: copy 'target' to both new columns
UPDATE public.scans 
SET 
  user_input_target = target,
  normalized_target = target,
  estimated_hosts = 1
WHERE user_input_target IS NULL;

-- Add comment for clarity
COMMENT ON COLUMN public.scans.user_input_target IS 'Original target string entered by user';
COMMENT ON COLUMN public.scans.normalized_target IS 'Normalized target used for actual scan (e.g., 192.168.1.0 -> 192.168.1.0/24)';
COMMENT ON COLUMN public.scans.estimated_hosts IS 'Estimated number of hosts in target range';