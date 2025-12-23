namespace MultiTenantApi.Security;

public sealed class TokenHardeningOptions
{
    public int MaxAccessTokenAgeMinutes { get; set; } = 15;
    public int ClockSkewSeconds { get; set; } = 30;

    public bool EnableJtiReplayProtection { get; set; } = true;
    public int JtiCacheMinutes { get; set; } = 20;
}