/* =====================================================================================
   Day-one fix for a legacy users table that stores passwords in PLAIN TEXT (or as
   unsalted SHA-256): convert every value to "legacy-sha256$<hex>" in place.

   - Nobody has to reset their password: the API still accepts the old password and
     re-hashes it with PBKDF2 (600k iterations, random salt) on the next successful login.
   - After this script the database no longer contains a single readable password.
   - Idempotent: rows already migrated (legacy-sha256$ / pbkdf2-sha256$) are skipped.

   Usage: run with @Apply = 0 (dry run, shows what would change), then with @Apply = 1.
   Requires SQL Server 2019+ for the UTF-8 collation, so non-ASCII passwords hash exactly
   like the API (Encoding.UTF8).
   ===================================================================================== */
SET NOCOUNT ON;
DECLARE @Apply BIT = 0;

SELECT COUNT(*) AS RowsToMigrate,
       SUM(CASE WHEN LEN(Password) = 64 AND Password NOT LIKE '%[^0-9a-fA-F]%' THEN 1 ELSE 0 END) AS AlreadyUnsaltedSha256,
       SUM(CASE WHEN LEN(Password) <> 64 OR Password LIKE '%[^0-9a-fA-F]%' THEN 1 ELSE 0 END) AS PlainText
FROM dbo.Users
WHERE Password IS NOT NULL
  AND Password NOT LIKE 'legacy-sha256$%'
  AND Password NOT LIKE 'pbkdf2-sha256$%';

IF @Apply = 1
BEGIN
    BEGIN TRANSACTION;
    UPDATE u
       SET Password = CASE
               -- Already an unsalted SHA-256 (64 hex chars) from an older system: just tag it.
               WHEN LEN(u.Password) = 64 AND u.Password NOT LIKE '%[^0-9a-fA-F]%' THEN 'legacy-sha256$' + LOWER(u.Password)
               -- Plain text: hash the UTF-8 bytes in the database.
               ELSE 'legacy-sha256$' + LOWER(CONVERT(VARCHAR(64),
                        HASHBYTES('SHA2_256', CAST(CAST(u.Password AS NVARCHAR(200)) COLLATE Latin1_General_100_CI_AS_SC_UTF8 AS VARCHAR(400))), 2))
           END
      FROM dbo.Users u
     WHERE u.Password IS NOT NULL
       AND u.Password NOT LIKE 'legacy-sha256$%'
       AND u.Password NOT LIKE 'pbkdf2-sha256$%';
    PRINT CONCAT(@@ROWCOUNT, ' password(s) converted.');
    COMMIT;
END
