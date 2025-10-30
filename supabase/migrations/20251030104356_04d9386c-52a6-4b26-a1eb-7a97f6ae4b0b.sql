-- Clean up old and irrelevant CVEs from the database

-- Step 1: Remove CVE references from findings for old CVEs (pre-2020)
UPDATE findings
SET cve_id = NULL
WHERE cve_id IN (
  SELECT cve_id FROM cve 
  WHERE cve_id ~ '^CVE-(199|200|201)[0-9]-'
  OR LOWER(description) LIKE ANY (ARRAY[
    '%windows 98%',
    '%windows 2000%',
    '%windows xp%',
    '%windows me%',
    '%wireless router%',
    '%broadband router%',
    '%wrt54g%',
    '%fritzbox router firmware%',
    '%access point%'
  ])
);

-- Step 2: Delete old and irrelevant CVEs
DELETE FROM cve 
WHERE cve_id ~ '^CVE-(199|200|201)[0-9]-'
OR LOWER(description) LIKE ANY (ARRAY[
  '%windows 98%',
  '%windows 2000%',
  '%windows xp%',
  '%windows me%',
  '%wireless router%',
  '%broadband router%',
  '%wrt54g%',
  '%fritzbox router firmware%',
  '%access point%'
]);