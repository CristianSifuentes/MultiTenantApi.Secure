namespace MultiTenantApi.Security.IdempotencyStore
{
    public interface IIdempotencyStore
    {
        Task<IdempotencyRecord?> GetAsync(string key, CancellationToken ct);
        Task<bool> TryStartAsync(string key, TimeSpan ttl, CancellationToken ct);
        Task CompleteAsync(string key, IdempotencyResponse response, TimeSpan ttl, CancellationToken ct);
    }

    public sealed record IdempotencyRecord(bool Completed, IdempotencyResponse? Response);

    public sealed record IdempotencyResponse(int StatusCode, string ContentType, byte[] Body);
}
