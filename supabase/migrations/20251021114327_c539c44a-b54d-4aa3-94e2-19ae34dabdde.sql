-- Create enum for user roles
CREATE TYPE public.app_role AS ENUM ('admin', 'user', 'consultant');

-- Create user_roles table
CREATE TABLE public.user_roles (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID REFERENCES auth.users(id) ON DELETE CASCADE NOT NULL,
    role public.app_role NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    UNIQUE (user_id, role)
);

-- Enable RLS on user_roles
ALTER TABLE public.user_roles ENABLE ROW LEVEL SECURITY;

-- Create security definer function to check roles
CREATE OR REPLACE FUNCTION public.has_role(_user_id UUID, _role public.app_role)
RETURNS BOOLEAN
LANGUAGE SQL
STABLE
SECURITY DEFINER
SET search_path = public
AS $$
  SELECT EXISTS (
    SELECT 1
    FROM public.user_roles
    WHERE user_id = _user_id
      AND role = _role
  )
$$;

-- RLS policies for user_roles table
CREATE POLICY "Users can view their own roles"
ON public.user_roles
FOR SELECT
USING (auth.uid() = user_id OR public.has_role(auth.uid(), 'admin'));

CREATE POLICY "Admins can insert roles"
ON public.user_roles
FOR INSERT
WITH CHECK (public.has_role(auth.uid(), 'admin'));

CREATE POLICY "Admins can update roles"
ON public.user_roles
FOR UPDATE
USING (public.has_role(auth.uid(), 'admin'));

CREATE POLICY "Admins can delete roles"
ON public.user_roles
FOR DELETE
USING (public.has_role(auth.uid(), 'admin'));

-- Update users table policies to allow admin access
CREATE POLICY "Admins can view all profiles"
ON public.users
FOR SELECT
USING (public.has_role(auth.uid(), 'admin') OR auth.uid() = user_id);

CREATE POLICY "Admins can update all profiles"
ON public.users
FOR UPDATE
USING (public.has_role(auth.uid(), 'admin') OR auth.uid() = user_id);

-- Update scans table policies to allow admin read access
CREATE POLICY "Admins can view all scans"
ON public.scans
FOR SELECT
USING (public.has_role(auth.uid(), 'admin') OR auth.uid() = user_id);

-- Update findings table policies to allow admin read access
CREATE POLICY "Admins can view all findings"
ON public.findings
FOR SELECT
USING (
  public.has_role(auth.uid(), 'admin') OR
  EXISTS (
    SELECT 1 FROM scans 
    WHERE scans.scan_id = findings.scan_id 
    AND scans.user_id = auth.uid()
  )
);

-- Update reports table policies to allow admin read access
CREATE POLICY "Admins can view all reports"
ON public.reports
FOR SELECT
USING (
  public.has_role(auth.uid(), 'admin') OR
  EXISTS (
    SELECT 1 FROM scans 
    WHERE scans.scan_id = reports.scan_id 
    AND scans.user_id = auth.uid()
  )
);