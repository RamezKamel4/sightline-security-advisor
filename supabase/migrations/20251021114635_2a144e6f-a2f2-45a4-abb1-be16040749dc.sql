-- Assign admin role to ramezkamel04@outlook.com
INSERT INTO public.user_roles (user_id, role)
VALUES ('e7ad96d7-e029-4486-8208-13510d614340', 'admin')
ON CONFLICT (user_id, role) DO NOTHING;