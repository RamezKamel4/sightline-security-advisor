
-- Update the scans table scan_depth check constraint to match the frontend values
ALTER TABLE public.scans DROP CONSTRAINT IF EXISTS scans_scan_depth_check;

ALTER TABLE public.scans ADD CONSTRAINT scans_scan_depth_check 
CHECK (scan_depth IN (
    'fast',
    'deep', 
    'aggressive'
));
