-- Add unique constraint on scan_id to allow upsert operations
ALTER TABLE reports ADD CONSTRAINT reports_scan_id_unique UNIQUE (scan_id);