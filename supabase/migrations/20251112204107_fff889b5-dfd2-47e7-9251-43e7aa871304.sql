-- Drop the restrictive policy that prevents users from seeing consultant/admin roles
DROP POLICY IF EXISTS "Users can view their own roles" ON public.user_roles;

-- Create a new policy that allows everyone to view consultant and admin roles
-- but only admins and the user themselves can see their own roles
CREATE POLICY "Users can view consultant and admin roles" 
ON public.user_roles 
FOR SELECT 
USING (
  -- Users can always see their own roles
  auth.uid() = user_id 
  OR 
  -- Everyone can see who the consultants and admins are (for dropdowns)
  role IN ('consultant', 'admin')
);