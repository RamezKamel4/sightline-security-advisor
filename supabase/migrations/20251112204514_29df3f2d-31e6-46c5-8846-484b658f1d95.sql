-- Create a policy to allow all authenticated users to view consultant and admin profiles
-- This is needed for consultant selection dropdowns
CREATE POLICY "Anyone can view consultant and admin profiles" 
ON public.users 
FOR SELECT 
USING (
  -- Allow if user is viewing their own profile
  auth.uid() = user_id 
  OR 
  -- Allow if user is an admin
  has_role(auth.uid(), 'admin')
  OR
  -- Allow viewing profiles of consultants and admins (for dropdowns)
  EXISTS (
    SELECT 1 FROM public.user_roles
    WHERE user_roles.user_id = users.user_id
    AND user_roles.role IN ('consultant', 'admin')
  )
);