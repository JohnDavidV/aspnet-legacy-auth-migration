/* How far along is the upgrade? Run it weekly. When "legacy" reaches 0 the compatibility
   code path can be deleted from the API; long-inactive legacy accounts can be forced to reset. */
SELECT Scheme, COUNT(*) AS Users
FROM (
    SELECT CASE
               WHEN Password LIKE 'pbkdf2-sha256$%' THEN 'modern (PBKDF2)'
               WHEN Password LIKE 'legacy-sha256$%' THEN 'legacy (upgraded on next login)'
               ELSE 'PLAIN TEXT - run 01_remove_plaintext_passwords.sql'
           END AS Scheme
    FROM dbo.Users
) s
GROUP BY Scheme;
