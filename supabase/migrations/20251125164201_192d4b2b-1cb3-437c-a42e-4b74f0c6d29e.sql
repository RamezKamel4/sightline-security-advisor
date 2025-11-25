-- Try to drop the cron job if it exists (ignore error if it doesn't)
DO $$
BEGIN
    PERFORM cron.unschedule('invoke-run-scheduled-scans');
EXCEPTION
    WHEN OTHERS THEN
        NULL; -- Ignore errors if cron job doesn't exist
END $$;

-- Drop the scheduled_scans table
DROP TABLE IF EXISTS public.scheduled_scans CASCADE;

-- Drop the database functions
DROP FUNCTION IF EXISTS public.get_due_scheduled_scans() CASCADE;
DROP FUNCTION IF EXISTS public.calculate_next_run(timestamp with time zone, text) CASCADE;