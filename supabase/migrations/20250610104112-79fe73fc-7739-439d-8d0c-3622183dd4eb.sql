
-- Fix the foreign key constraint to reference auth.users instead of public.users
ALTER TABLE public.scans 
DROP CONSTRAINT IF EXISTS scans_user_id_fkey;

ALTER TABLE public.scans 
ADD CONSTRAINT scans_user_id_fkey 
FOREIGN KEY (user_id) REFERENCES auth.users(id) ON DELETE CASCADE;
