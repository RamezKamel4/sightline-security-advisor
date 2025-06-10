
-- Update the scans table check constraint to match the frontend values
ALTER TABLE public.scans DROP CONSTRAINT IF EXISTS scans_profile_check;

ALTER TABLE public.scans ADD CONSTRAINT scans_profile_check 
CHECK (profile IN (
    'quick',
    'standard', 
    'comprehensive',
    'web-apps',
    'databases',
    'remote-access'
));
