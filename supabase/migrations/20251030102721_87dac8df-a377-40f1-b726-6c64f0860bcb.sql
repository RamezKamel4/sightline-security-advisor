-- Step 1: Remove CVE references from findings for irrelevant CVEs
UPDATE findings
SET cve_id = NULL
WHERE cve_id IN (
  SELECT cve_id FROM cve 
  WHERE LOWER(description) LIKE ANY (ARRAY[
    '%tenda%',
    '%tp-link%',
    '%router%',
    '%firmware%',
    '%d-link%',
    '%zyxel%',
    '%iot%',
    '%camera%',
    '%modem%',
    '%printer%',
    '%netgear%',
    '%linksys%',
    '%buffalo%',
    '%asus router%',
    '%belkin%',
    '%huawei router%',
    '%weblogic%'
  ])
  OR LOWER(title) LIKE ANY (ARRAY[
    '%tenda%',
    '%tp-link%',
    '%router%',
    '%firmware%',
    '%d-link%',
    '%zyxel%',
    '%iot%',
    '%camera%',
    '%modem%',
    '%printer%',
    '%netgear%',
    '%linksys%',
    '%buffalo%',
    '%asus router%',
    '%belkin%',
    '%huawei router%',
    '%weblogic%'
  ])
);

-- Step 2: Delete irrelevant CVEs from the database
DELETE FROM cve 
WHERE LOWER(description) LIKE ANY (ARRAY[
  '%tenda%',
  '%tp-link%',
  '%router%',
  '%firmware%',
  '%d-link%',
  '%zyxel%',
  '%iot%',
  '%camera%',
  '%modem%',
  '%printer%',
  '%netgear%',
  '%linksys%',
  '%buffalo%',
  '%asus router%',
  '%belkin%',
  '%huawei router%',
  '%weblogic%'
])
OR LOWER(title) LIKE ANY (ARRAY[
  '%tenda%',
  '%tp-link%',
  '%router%',
  '%firmware%',
  '%d-link%',
  '%zyxel%',
  '%iot%',
  '%camera%',
  '%modem%',
  '%printer%',
  '%netgear%',
  '%linksys%',
  '%buffalo%',
  '%asus router%',
  '%belkin%',
  '%huawei router%',
  '%weblogic%'
]);