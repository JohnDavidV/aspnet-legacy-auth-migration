using System.Security.Cryptography;
using System.Text;

namespace LegacyAuth.Api.Security;

/// <summary>
/// Expiring, tamper-proof download links (e.g. "download your employment certificate").
///
/// The legacy pattern this replaces was <c>SHA256(id + "|" + secret + "|" + yyyyMMdd)</c>:
/// a plain hash (length-extension prone, not a MAC), day-granular, with the secret mixed in
/// as data. Here the signature is HMAC-SHA256 over a canonical payload with an exact
/// expiry, and the link is bound to its purpose so a token for one resource type cannot
/// be replayed against another.
/// </summary>
public sealed class SignedLinks
{
    private readonly byte[] _key;
    private readonly TimeProvider _time;

    public SignedLinks(byte[] key, TimeProvider? time = null)
    {
        if (key.Length < 32) throw new ArgumentException("Use a key of at least 256 bits.", nameof(key));
        _key = key;
        _time = time ?? TimeProvider.System;
    }

    public (long Expires, string Signature) Sign(string purpose, string resourceId, TimeSpan validFor)
    {
        var expires = _time.GetUtcNow().Add(validFor).ToUnixTimeSeconds();
        return (expires, Compute(purpose, resourceId, expires));
    }

    public bool Verify(string purpose, string resourceId, long expires, string? signature)
    {
        if (string.IsNullOrEmpty(signature)) return false;
        if (_time.GetUtcNow().ToUnixTimeSeconds() > expires) return false;
        byte[] given;
        try
        {
            given = Base64UrlDecode(signature);
        }
        catch (FormatException)
        {
            return false;
        }
        var expected = Base64UrlDecode(Compute(purpose, resourceId, expires));
        return CryptographicOperations.FixedTimeEquals(given, expected);
    }

    private string Compute(string purpose, string resourceId, long expires)
    {
        // Length-prefixed fields: "a|bc" and "ab|c" can never produce the same payload.
        var payload = $"{purpose.Length}:{purpose}|{resourceId.Length}:{resourceId}|{expires}";
        var mac = HMACSHA256.HashData(_key, Encoding.UTF8.GetBytes(payload));
        return Convert.ToBase64String(mac).TrimEnd('=').Replace('+', '-').Replace('/', '_');
    }

    private static byte[] Base64UrlDecode(string value)
    {
        var s = value.Replace('-', '+').Replace('_', '/');
        return Convert.FromBase64String(s.PadRight(s.Length + (4 - s.Length % 4) % 4, '='));
    }
}
