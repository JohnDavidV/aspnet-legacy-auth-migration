using System.Collections.Concurrent;

namespace LegacyAuth.Api.Users;

public sealed record User(string Username, string DisplayName, string PasswordHash, bool MustChangePassword = false);

public interface IUserStore
{
    User? Find(string username);
    void UpdatePasswordHash(string username, string newHash, bool mustChangePassword);
}

/// <summary>
/// In-memory store seeded with the three kinds of rows found in a legacy table.
/// In production this is a SQL table (see sql/), accessed with parameterized queries.
/// </summary>
public sealed class InMemoryUserStore : IUserStore
{
    private readonly ConcurrentDictionary<string, User> _users = new(StringComparer.OrdinalIgnoreCase);

    public InMemoryUserStore(IEnumerable<User> seed)
    {
        foreach (var u in seed) _users[u.Username] = u;
    }

    public User? Find(string username) => _users.TryGetValue(username.Trim(), out var u) ? u : null;

    public void UpdatePasswordHash(string username, string newHash, bool mustChangePassword)
    {
        _users.AddOrUpdate(username,
            _ => throw new KeyNotFoundException(username),
            (_, u) => u with { PasswordHash = newHash, MustChangePassword = mustChangePassword });
    }

    public IReadOnlyCollection<User> All() => _users.Values.ToArray();
}
