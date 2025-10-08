-- Add host_info column to scans table to store OS detection, MAC address, and other host metadata
ALTER TABLE scans 
ADD COLUMN IF NOT EXISTS host_info JSONB DEFAULT NULL;

-- Add a comment to document the column
COMMENT ON COLUMN scans.host_info IS 'Stores host metadata from nmap scan including OS detection, MAC address, network distance, hostnames, etc.';