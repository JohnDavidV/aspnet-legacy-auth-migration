using LegacyAuth.Api.Security;

namespace LegacyAuth.Api.Users;

public enum LoginStatus { Ok, InvalidCredentials, LockedOut, MustChangePassword }

public sealed record LoginResult(LoginStatus Status, User? User = null, TimeSpan? RetryAfter = null, bool Upgraded = false);

public sealed class AuthService(IUserStore users, PasswordHasher hasher, LoginThrottle throttle)
{
    // Verified against a dummy hash when the user does not exist, so the response time does
    // not reveal which usernames are valid.
    private static readonly string DummyHash = new PasswordHasher(10_000).Hash("dummy-password");

    public LoginResult Login(string username, string password)
    {
        var locked = throttle.LockedFor(username);
        if (locked is not null) return new LoginResult(LoginStatus.LockedOut, RetryAfter: locked);

        var user = users.Find(username);
        var result = hasher.Verify(user?.PasswordHash ?? DummyHash, password);
        if (user is null || result == PasswordVerification.Failed)
        {
            throttle.RegisterFailure(username);
            return new LoginResult(LoginStatus.InvalidCredentials);
        }

        throttle.RegisterSuccess(username);
        var upgraded = false;
        if (result == PasswordVerification.SuccessRehashNeeded)
        {
            // Transparent upgrade: the user never notices, the database gets a modern hash.
            users.UpdatePasswordHash(user.Username, hasher.Hash(password), user.MustChangePassword);
            upgraded = true;
        }
        return new LoginResult(user.MustChangePassword ? LoginStatus.MustChangePassword : LoginStatus.Ok, user, Upgraded: upgraded);
    }

    public IReadOnlyList<string> ChangePassword(string username, string current, string next)
    {
        var errors = PasswordPolicy.Validate(next, username).ToList();
        var user = users.Find(username);
        if (user is null || hasher.Verify(user.PasswordHash, current) == PasswordVerification.Failed)
            errors.Insert(0, "The current password is not correct.");
        else if (current == next)
            errors.Add("The new password must be different from the current one.");
        if (errors.Count == 0) users.UpdatePasswordHash(user!.Username, hasher.Hash(next), mustChangePassword: false);
        return errors;
    }
}

public static class PasswordPolicy
{
    // Length beats composition rules (NIST SP 800-63B); block the obvious ones.
    private static readonly HashSet<string> Common = new(StringComparer.OrdinalIgnoreCase)
    {
        "password", "password1", "123456789", "1234567890", "qwerty123", "contraseña", "administrador",
    };

    public static IEnumerable<string> Validate(string password, string username)
    {
        if (string.IsNullOrEmpty(password) || password.Length < 10) yield return "Use at least 10 characters.";
        if (password?.Length > 128) yield return "Use at most 128 characters.";
        if (password is not null && Common.Contains(password)) yield return "That password is too common.";
        if (password is not null && password.Contains(username.Trim(), StringComparison.OrdinalIgnoreCase))
            yield return "The password must not contain the username.";
    }
}
