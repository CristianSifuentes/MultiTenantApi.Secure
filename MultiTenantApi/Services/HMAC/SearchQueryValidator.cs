using System.Text.RegularExpressions;

namespace MultiTenantApi.Security;

public static class SearchQueryValidator
{
    // Limits tuned to reduce abuse while keeping UX reasonable.
    private const int MinQueryLen = 2;
    private const int MaxQueryLen = 120;
    private const int MaxChannels = 5;
    private const int MaxCursorLen = 32;

    // Allow a conservative set of characters (deny-by-default).
    // This reduces log injection, weird encodings, and “fuzzing surface”.
    private static readonly Regex QueryWhitelist =
        new(@"^[\p{L}\p{N}\s\-\._:@/]+$", RegexOptions.Compiled);

    private static readonly HashSet<string> AllowedChannels =
        new(StringComparer.OrdinalIgnoreCase) { "web", "api" };

    public static (bool ok, string? error) Validate(SearchQuery q)
    {
        // 1) Query required
        if (string.IsNullOrWhiteSpace(q.Query))
            return (false, "Query is required.");

        var query = q.Query.Trim();

        // 2) Size limits
        if (query.Length < MinQueryLen)
            return (false, $"Query must be at least {MinQueryLen} chars.");

        if (query.Length > MaxQueryLen)
            return (false, $"Query must be <= {MaxQueryLen} chars.");

        // 3) Format whitelist (deny-by-default)
        if (!QueryWhitelist.IsMatch(query))
            return (false, "Query contains unsupported characters.");

        // 4) Channels whitelist
        if (q.Channels is { Length: > 0 })
        {
            if (q.Channels.Length > MaxChannels)
                return (false, $"Too many channels (max {MaxChannels}).");

            foreach (var ch in q.Channels)
            {
                if (string.IsNullOrWhiteSpace(ch))
                    return (false, "Channels contains empty value.");

                if (!AllowedChannels.Contains(ch.Trim()))
                    return (false, $"Channel '{ch}' is not allowed.");
            }
        }

        // 5) Time range validation (ABUSE prevention + sanity)
        if (q.FromUtc.HasValue && q.ToUtc.HasValue)
        {
            if (q.FromUtc > q.ToUtc)
                return (false, "FromUtc must be <= ToUtc.");
        }

        // Keep range bounded (avoid “search everything forever”)
        // Example: allow max 31 days of range when both are present
        if (q.FromUtc.HasValue && q.ToUtc.HasValue)
        {
            var range = q.ToUtc.Value - q.FromUtc.Value;
            if (range > TimeSpan.FromDays(31))
                return (false, "Date range too large (max 31 days).");
        }

        // 6) Cursor token: bounded + numeric-only (for demo in-memory cursor)
        if (!string.IsNullOrWhiteSpace(q.NextPageToken))
        {
            var t = q.NextPageToken.Trim();
            if (t.Length > MaxCursorLen)
                return (false, "NextPageToken is too long.");

            // For this in-memory demo token is an int offset.
            // If later you migrate to opaque cursor, replace this with Base64Url + signature check.
            if (!int.TryParse(t, out var parsed) || parsed < 0)
                return (false, "NextPageToken is invalid.");
        }

        // 7) Limit handled in endpoint via clamp; optionally enforce here too
        if (q.Limit.HasValue && (q.Limit.Value < 1 || q.Limit.Value > 100))
            return (false, "Limit must be between 1 and 100.");

        return (true, null);
    }

    // Avoid returning full text; helps data minimization + prevents huge payload echoes.
    public static string SafePreview(string? input, int maxLen)
    {
        if (string.IsNullOrEmpty(input))
            return string.Empty;

        var s = input.Replace("\r", " ").Replace("\n", " ").Trim();
        if (s.Length <= maxLen) return s;

        return s[..maxLen] + "…";
    }
}
