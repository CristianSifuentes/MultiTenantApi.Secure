namespace MultiTenantApi.Common;

public sealed class SyntheticIdOptions
{
    /// <summary>
    /// Base64-encoded 32-byte key (HMAC-SHA256). Store in KeyVault/secret store, not in code.
    /// </summary>
    public string KeyBase64 { get; init; } = string.Empty;

    /// <summary>
    /// Environment/namespace prefix to prevent cross-environment correlation (dev/prod).
    /// </summary>
    public string Namespace { get; init; } = "default";
}

public sealed class RateLimitOptions
{
    public int PerIdentityPerMinute { get; init; } = 300;
    public int BurstPer10Seconds { get; init; } = 50;
}
