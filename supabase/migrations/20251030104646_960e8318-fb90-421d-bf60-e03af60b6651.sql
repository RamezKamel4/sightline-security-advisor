-- Remove Tenda AC18 CVE from findings
UPDATE findings
SET cve_id = NULL
WHERE cve_id = 'CVE-2025-11327';

-- Delete the Tenda AC18 CVE from database
DELETE FROM cve 
WHERE cve_id = 'CVE-2025-11327';