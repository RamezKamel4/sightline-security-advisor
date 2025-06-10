
-- Update scan_id format to SCAN-YYYYMMDD-ID pattern
-- First, let's create a function to generate the new scan ID format
CREATE OR REPLACE FUNCTION generate_scan_id()
RETURNS TEXT AS $$
DECLARE
    date_part TEXT;
    random_id TEXT;
BEGIN
    -- Get current date in YYYYMMDD format
    date_part := to_char(NOW(), 'YYYYMMDD');
    
    -- Generate a random 6-character alphanumeric ID
    random_id := upper(substring(gen_random_uuid()::text from 1 for 6));
    
    -- Return formatted scan ID
    RETURN 'SCAN-' || date_part || '-' || random_id;
END;
$$ LANGUAGE plpgsql;

-- Update the scans table to use the new ID format
ALTER TABLE public.scans 
ALTER COLUMN scan_id SET DEFAULT generate_scan_id();

-- Update any existing scan IDs to follow the new format (optional - only if you want to update existing data)
-- This will update existing records to use the new format
UPDATE public.scans 
SET scan_id = generate_scan_id() 
WHERE scan_id ~ '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$';
