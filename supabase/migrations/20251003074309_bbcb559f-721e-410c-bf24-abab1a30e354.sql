-- Add nmap command logging to scans table
ALTER TABLE scans ADD COLUMN IF NOT EXISTS nmap_cmd text;
ALTER TABLE scans ADD COLUMN IF NOT EXISTS nmap_output text;

-- Add agent support fields
ALTER TABLE scans ADD COLUMN IF NOT EXISTS scan_source text DEFAULT 'backend';
ALTER TABLE scans ADD COLUMN IF NOT EXISTS use_arp_discovery boolean DEFAULT false;