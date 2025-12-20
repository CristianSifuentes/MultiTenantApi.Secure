using System.Security.Cryptography;
using System.Text;

namespace MultiTenantApi.Security;

public sealed record RefreshTokenPair(string AccessToken, string RefreshToken);

public sealed class RefreshTokenService
{
    // tokenHash -> record
    private readonly Dictionary<string, (string subject, bool revoked, DateTimeOffset exp, string family)> _store = new();

    public (string RefreshToken, string RefreshTokenHash) IssueRefreshToken(string subject, TimeSpan lifetime, string family)
    {
        var token = Convert.ToBase64String(RandomNumberGenerator.GetBytes(64));
        var hash = Hash(token);
        _store[hash] = (subject, revoked: false, exp: DateTimeOffset.UtcNow.Add(lifetime), family);
        return (token, hash);
    }

    public bool TryRotate(string subject, string presentedRefreshToken, TimeSpan lifetime, out (string newToken, string newHash) rotated, out string? error)
    {
        rotated = default;
        error = null;

        var presentedHash = Hash(presentedRefreshToken);

        if (!_store.TryGetValue(presentedHash, out var rec))
        {
            error = "invalid_refresh_token";
            return false;
        }

        // reuse detection / stolen token signal
        if (rec.revoked)
        {
            RevokeFamily(rec.family);
            error = "refresh_token_reuse_detected";
            return false;
        }

        if (rec.subject != subject)
        {
            error = "refresh_token_subject_mismatch";
            return false;
        }

        if (rec.exp <= DateTimeOffset.UtcNow)
        {
            error = "refresh_token_expired";
            return false;
        }

        // rotate: revoke old, issue new in same family
        _store[presentedHash] = (rec.subject, revoked: true, rec.exp, rec.family);
        var (t, h) = IssueRefreshToken(subject, lifetime, rec.family);
        rotated = (t, h);
        return true;
    }

    private void RevokeFamily(string family)
    {
        foreach (var k in _store.Keys.ToList())
        {
            var rec = _store[k];
            if (rec.family == family)
                _store[k] = (rec.subject, revoked: true, rec.exp, rec.family);
        }
    }

    private static string Hash(string token)
    {
        using var sha = SHA256.Create();
        var bytes = sha.ComputeHash(Encoding.UTF8.GetBytes(token));
        return Convert.ToBase64String(bytes);
    }
}
