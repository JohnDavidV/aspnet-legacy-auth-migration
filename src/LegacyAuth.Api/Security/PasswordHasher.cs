using System.Security.Cryptography;
using System.Text;

namespace LegacyAuth.Api.Security;

public enum PasswordVerification
{
    Failed,
    Success,
    /// <summary>Correct password, but stored with an outdated scheme: re-hash it now.</summary>
    SuccessRehashNeeded,
}

/// <summary>
/// Versioned password hashing with transparent upgrades.
///
/// Stored formats (the prefix tells which algorithm produced the value):
///   pbkdf2-sha256$&lt;iterations&gt;$&lt;salt b64&gt;$&lt;hash b64&gt;   current scheme
///   legacy-sha256$&lt;hex&gt;                                 unsalted SHA-256 of the old system
///   (anything else)                                        plain text left by the old system
///
/// Legacy values are still accepted - once - and the caller re-hashes them with the
/// current scheme on that successful login. Plain text can be removed from the database on
/// day one by converting it to legacy-sha256 in SQL (see sql/), without forcing a reset.
/// </summary>
public sealed class PasswordHasher
{
    public const string CurrentPrefix = "pbkdf2-sha256";
    public const string LegacySha256Prefix = "legacy-sha256";

    private const int SaltSize = 16;
    private const int HashSize = 32;
    private readonly int _iterations;

    /// <param name="iterations">OWASP (2023+) recommends 600,000 for PBKDF2-HMAC-SHA256.</param>
    public PasswordHasher(int iterations = 600_000)
    {
        if (iterations < 10_000) throw new ArgumentOutOfRangeException(nameof(iterations));
        _iterations = iterations;
    }

    public string Hash(string password)
    {
        ArgumentException.ThrowIfNullOrEmpty(password);
        var salt = RandomNumberGenerator.GetBytes(SaltSize);
        var hash = Rfc2898DeriveBytes.Pbkdf2(password, salt, _iterations, HashAlgorithmName.SHA256, HashSize);
        return $"{CurrentPrefix}${_iterations}${Convert.ToBase64String(salt)}${Convert.ToBase64String(hash)}";
    }

    public PasswordVerification Verify(string stored, string password)
    {
        if (string.IsNullOrEmpty(stored) || password is null) return PasswordVerification.Failed;

        var parts = stored.Split('$');
        if (parts[0] == CurrentPrefix)
        {
            if (parts.Length != 4 || !int.TryParse(parts[1], out var iterations)) return PasswordVerification.Failed;
            byte[] salt, expected;
            try
            {
                salt = Convert.FromBase64String(parts[2]);
                expected = Convert.FromBase64String(parts[3]);
            }
            catch (FormatException)
            {
                return PasswordVerification.Failed;
            }
            var actual = Rfc2898DeriveBytes.Pbkdf2(password, salt, iterations, HashAlgorithmName.SHA256, expected.Length);
            if (!CryptographicOperations.FixedTimeEquals(actual, expected)) return PasswordVerification.Failed;
            // Also upgrade when the work factor was raised since this hash was created.
            return iterations < _iterations ? PasswordVerification.SuccessRehashNeeded : PasswordVerification.Success;
        }

        if (parts[0] == LegacySha256Prefix && parts.Length == 2)
        {
            return FixedTimeEqualsText(Sha256Hex(password), parts[1].ToLowerInvariant())
                ? PasswordVerification.SuccessRehashNeeded
                : PasswordVerification.Failed;
        }

        // Plain text from the old system (should not exist after running the SQL migration).
        return FixedTimeEqualsText(password, stored) ? PasswordVerification.SuccessRehashNeeded : PasswordVerification.Failed;
    }

    public static string Sha256Hex(string value) =>
        Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(value))).ToLowerInvariant();

    private static bool FixedTimeEqualsText(string a, string b) =>
        CryptographicOperations.FixedTimeEquals(Encoding.UTF8.GetBytes(a), Encoding.UTF8.GetBytes(b));
}
