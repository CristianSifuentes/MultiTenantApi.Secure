namespace MultiTenantApi.Infrastructure
{
    public interface ITokenRevocationStore
    {
        Task RevokeAsync(string jti, TimeSpan ttl, CancellationToken ct);
        Task<bool> IsRevokedAsync(string jti, CancellationToken ct);

        // Optional: anti-replay (token reuse detection)
        Task<bool> TryMarkSeenAsync(string jti, TimeSpan ttl, CancellationToken ct);
    }
}
