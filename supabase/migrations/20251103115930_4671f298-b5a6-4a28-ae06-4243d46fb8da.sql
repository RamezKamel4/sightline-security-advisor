-- Add status field to findings table to track vulnerability confidence
-- status values: vulnerable, unconfirmed, info, no_cves_found, low_risk
ALTER TABLE findings ADD COLUMN IF NOT EXISTS status TEXT DEFAULT 'info';

-- Add index for faster status filtering
CREATE INDEX IF NOT EXISTS idx_findings_status ON findings(status);

-- Add comment to clarify difference between state and status
COMMENT ON COLUMN findings.state IS 'Port state from nmap: open, closed, filtered';
COMMENT ON COLUMN findings.status IS 'Vulnerability status: vulnerable, unconfirmed, info, no_cves_found, low_risk';
COMMENT ON COLUMN findings.detection_methods IS 'Evidence and detection sources as JSON including recommendations';
