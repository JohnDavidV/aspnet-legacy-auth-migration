using LegacyAuth.Api.Security;
using LegacyAuth.Api.Users;
using Xunit;

namespace LegacyAuth.Tests;

public sealed class ManualTime(DateTimeOffset start) : TimeProvider
{
    public DateTimeOffset Now { get; set; } = start;
    public override DateTimeOffset GetUtcNow() => Now;
    public void Advance(TimeSpan by) => Now += by;
}

public class PasswordHasherTests
{
    private readonly PasswordHasher _hasher = new(iterations: 10_000);

    [Fact]
    public void Hash_IsSaltedAndVersioned()
    {
        var a = _hasher.Hash("correct horse battery");
        var b = _hasher.Hash("correct horse battery");
        Assert.StartsWith("pbkdf2-sha256$10000$", a);
        Assert.NotEqual(a, b); // random salt
        Assert.Equal(PasswordVerification.Success, _hasher.Verify(a, "correct horse battery"));
        Assert.Equal(PasswordVerification.Failed, _hasher.Verify(a, "wrong"));
    }

    [Fact]
    public void LegacySha256_IsAcceptedAndFlaggedForRehash()
    {
        var stored = "legacy-sha256$" + PasswordHasher.Sha256Hex("old-secret");
        Assert.Equal(PasswordVerification.SuccessRehashNeeded, _hasher.Verify(stored, "old-secret"));
        Assert.Equal(PasswordVerification.Failed, _hasher.Verify(stored, "Old-secret"));
    }

    [Fact]
    public void PlainText_IsAcceptedOnceAndFlaggedForRehash()
    {
        Assert.Equal(PasswordVerification.SuccessRehashNeeded, _hasher.Verify("hunter22", "hunter22"));
        Assert.Equal(PasswordVerification.Failed, _hasher.Verify("hunter22", "hunter2"));
    }

    [Fact]
    public void RaisedWorkFactor_TriggersRehash()
    {
        var weak = new PasswordHasher(10_000).Hash("passphrase-x");
        Assert.Equal(PasswordVerification.SuccessRehashNeeded, new PasswordHasher(20_000).Verify(weak, "passphrase-x"));
    }

    [Theory]
    [InlineData("")]
    [InlineData("pbkdf2-sha256$abc$xx$yy")]
    [InlineData("pbkdf2-sha256$10000$not-base64!$x")]
    [InlineData("pbkdf2-sha256$10000")]
    public void MalformedHashes_FailClosed(string stored)
    {
        Assert.Equal(PasswordVerification.Failed, _hasher.Verify(stored, "anything"));
    }
}

public class SignedLinksTests
{
    private static readonly byte[] Key = Enumerable.Range(0, 32).Select(i => (byte)i).ToArray();

    [Fact]
    public void ValidLink_Verifies()
    {
        var links = new SignedLinks(Key);
        var (exp, sig) = links.Sign("certificate", "ana", TimeSpan.FromHours(1));
        Assert.True(links.Verify("certificate", "ana", exp, sig));
    }

    [Fact]
    public void TamperedFields_AreRejected()
    {
        var links = new SignedLinks(Key);
        var (exp, sig) = links.Sign("certificate", "ana", TimeSpan.FromHours(1));
        Assert.False(links.Verify("certificate", "luis", exp, sig));       // other resource
        Assert.False(links.Verify("payslip", "ana", exp, sig));            // other purpose
        Assert.False(links.Verify("certificate", "ana", exp + 3600, sig)); // extended expiry
        Assert.False(links.Verify("certificate", "ana", exp, sig[..^2] + "AA"));
        Assert.False(links.Verify("certificate", "ana", exp, "%%%"));
        Assert.False(links.Verify("certificate", "ana", exp, null));
    }

    [Fact]
    public void Link_Expires()
    {
        var time = new ManualTime(DateTimeOffset.Parse("2026-01-01T00:00:00Z"));
        var links = new SignedLinks(Key, time);
        var (exp, sig) = links.Sign("certificate", "ana", TimeSpan.FromMinutes(10));
        time.Advance(TimeSpan.FromMinutes(11));
        Assert.False(links.Verify("certificate", "ana", exp, sig));
    }

    [Fact]
    public void ShortKeys_AreRefused()
    {
        Assert.Throws<ArgumentException>(() => new SignedLinks(new byte[16]));
    }
}

public class LoginThrottleTests
{
    [Fact]
    public void LocksAfterFreeAttempts_WithExponentialBackoff()
    {
        var time = new ManualTime(DateTimeOffset.Parse("2026-01-01T00:00:00Z"));
        var throttle = new LoginThrottle(time, freeAttempts: 3, baseLock: TimeSpan.FromSeconds(30));
        for (var i = 0; i < 2; i++) throttle.RegisterFailure("Ana");
        Assert.Null(throttle.LockedFor("ana"));

        throttle.RegisterFailure(" ANA "); // same bucket
        Assert.Equal(TimeSpan.FromSeconds(30), throttle.LockedFor("ana"));

        time.Advance(TimeSpan.FromSeconds(31));
        Assert.Null(throttle.LockedFor("ana"));
        throttle.RegisterFailure("ana");
        Assert.Equal(TimeSpan.FromSeconds(60), throttle.LockedFor("ana"));
    }

    [Fact]
    public void Success_Resets()
    {
        var throttle = new LoginThrottle(freeAttempts: 1);
        throttle.RegisterFailure("ana");
        throttle.RegisterSuccess("ana");
        Assert.Null(throttle.LockedFor("ana"));
    }
}

public class AuthServiceTests
{
    private readonly PasswordHasher _hasher = new(iterations: 10_000);

    private (AuthService Auth, InMemoryUserStore Store) Build(params User[] users)
    {
        var store = new InMemoryUserStore(users);
        return (new AuthService(store, _hasher, new LoginThrottle(freeAttempts: 3)), store);
    }

    [Fact]
    public void LegacyUser_IsUpgradedTransparentlyOnLogin()
    {
        var (auth, store) = Build(new User("luis", "Luis", "legacy-sha256$" + PasswordHasher.Sha256Hex("old-pass")));
        var result = auth.Login("luis", "old-pass");
        Assert.Equal(LoginStatus.Ok, result.Status);
        Assert.True(result.Upgraded);
        Assert.StartsWith("pbkdf2-sha256$", store.Find("luis")!.PasswordHash);
        // and the same password keeps working with the new hash
        Assert.False(auth.Login("luis", "old-pass").Upgraded);
    }

    [Fact]
    public void UnknownUserAndWrongPassword_LookTheSame()
    {
        var (auth, _) = Build(new User("ana", "Ana", _hasher.Hash("right-password")));
        Assert.Equal(LoginStatus.InvalidCredentials, auth.Login("nobody", "x").Status);
        Assert.Equal(LoginStatus.InvalidCredentials, auth.Login("ana", "x").Status);
    }

    [Fact]
    public void LockedAccount_RejectsEvenTheRightPassword()
    {
        var (auth, _) = Build(new User("ana", "Ana", _hasher.Hash("right-password")));
        for (var i = 0; i < 3; i++) auth.Login("ana", "wrong");
        Assert.Equal(LoginStatus.LockedOut, auth.Login("ana", "right-password").Status);
    }

    [Fact]
    public void ForcedChange_ThenPolicyIsEnforced()
    {
        var (auth, store) = Build(new User("maria", "María", "maria2015", MustChangePassword: true));
        Assert.Equal(LoginStatus.MustChangePassword, auth.Login("maria", "maria2015").Status);

        Assert.Contains("Use at least 10 characters.", auth.ChangePassword("maria", "maria2015", "short"));
        Assert.Contains("The password must not contain the username.", auth.ChangePassword("maria", "maria2015", "maria-is-great-2026"));
        Assert.Contains("The current password is not correct.", auth.ChangePassword("maria", "wrong", "a-good-long-passphrase"));

        Assert.Empty(auth.ChangePassword("maria", "maria2015", "a-good-long-passphrase"));
        Assert.False(store.Find("maria")!.MustChangePassword);
        Assert.Equal(LoginStatus.Ok, auth.Login("maria", "a-good-long-passphrase").Status);
    }
}
