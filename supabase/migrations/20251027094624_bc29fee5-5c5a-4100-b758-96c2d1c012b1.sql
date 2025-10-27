-- Add cve_enriched flag to scans table to track if CVE data has been fetched
ALTER TABLE scans 
ADD COLUMN IF NOT EXISTS cve_enriched BOOLEAN NOT NULL DEFAULT false;

-- Add index for faster lookups
CREATE INDEX IF NOT EXISTS idx_scans_cve_enriched ON scans(cve_enriched);

-- Add comment for documentation
COMMENT ON COLUMN scans.cve_enriched IS 'Indicates whether CVE enrichment from NVD has been completed for this scan';