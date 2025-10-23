-- Fix security warnings by setting search_path for all functions
ALTER FUNCTION public.update_updated_at_column() SET search_path = public;
ALTER FUNCTION public.calculate_next_run(timestamp with time zone, text) SET search_path = public;
ALTER FUNCTION public.get_due_scheduled_scans() SET search_path = public;