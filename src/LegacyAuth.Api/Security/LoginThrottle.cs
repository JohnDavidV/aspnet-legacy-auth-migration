using System.Collections.Concurrent;

namespace LegacyAuth.Api.Security;

/// <summary>
/// Per-account brute-force protection: after <c>freeAttempts</c> failures the account is
/// locked for an exponentially growing period (30 s, 60 s, 120 s ... capped). A success
/// resets the counter. Keyed by normalised username so "Admin" and "admin " share a bucket.
/// In a web farm this state would live in Redis or the database; the policy is the same.
/// </summary>
public sealed class LoginThrottle
{
    private readonly ConcurrentDictionary<string, (int Failures, DateTimeOffset LockedUntil)> _state = new();
    private readonly TimeProvider _time;
    private readonly int _freeAttempts;
    private readonly TimeSpan _baseLock;
    private readonly TimeSpan _maxLock;

    public LoginThrottle(TimeProvider? time = null, int freeAttempts = 5, TimeSpan? baseLock = null, TimeSpan? maxLock = null)
    {
        _time = time ?? TimeProvider.System;
        _freeAttempts = freeAttempts;
        _baseLock = baseLock ?? TimeSpan.FromSeconds(30);
        _maxLock = maxLock ?? TimeSpan.FromMinutes(15);
    }

    private static string Key(string username) => username.Trim().ToLowerInvariant();

    /// <summary>Remaining lock time, or null if a login attempt is allowed now.</summary>
    public TimeSpan? LockedFor(string username)
    {
        if (!_state.TryGetValue(Key(username), out var s)) return null;
        var remaining = s.LockedUntil - _time.GetUtcNow();
        return remaining > TimeSpan.Zero ? remaining : null;
    }

    public void RegisterFailure(string username)
    {
        _state.AddOrUpdate(Key(username),
            _ => (1, DateTimeOffset.MinValue),
            (_, s) =>
            {
                var failures = s.Failures + 1;
                if (failures < _freeAttempts) return (failures, s.LockedUntil);
                var exponent = Math.Min(failures - _freeAttempts, 10);
                var lockFor = TimeSpan.FromTicks(Math.Min(_baseLock.Ticks * (1L << exponent), _maxLock.Ticks));
                return (failures, _time.GetUtcNow() + lockFor);
            });
    }

    public void RegisterSuccess(string username) => _state.TryRemove(Key(username), out _);
}
