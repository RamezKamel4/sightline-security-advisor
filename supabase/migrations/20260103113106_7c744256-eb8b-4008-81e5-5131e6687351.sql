-- Remove policies that caused recursion between reports <-> scans/users
DROP POLICY IF EXISTS "Consultants can view scans with pending reports" ON public.scans;
DROP POLICY IF EXISTS "Consultants can view users for pending reports" ON public.users;