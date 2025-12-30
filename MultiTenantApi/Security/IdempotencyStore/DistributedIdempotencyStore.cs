using System.Text.Json;
using Microsoft.Extensions.Caching.Distributed;

namespace MultiTenantApi.Security.IdempotencyStore
{

    public sealed class DistributedIdempotencyStore : IIdempotencyStore
    {
        private readonly IDistributedCache _cache;

        public DistributedIdempotencyStore(IDistributedCache cache) => _cache = cache;

        private static string Key(string k) => $"idem:{k}";

        public async Task<IdempotencyRecord?> GetAsync(string key, CancellationToken ct)
        {
            var bytes = await _cache.GetAsync(Key(key), ct);
            if (bytes is null) return null;
            return JsonSerializer.Deserialize<IdempotencyRecord>(bytes);
        }

        public async Task<bool> TryStartAsync(string key, TimeSpan ttl, CancellationToken ct)
        {
            var existing = await _cache.GetAsync(Key(key), ct);
            if (existing is not null) return false;

            var rec = new IdempotencyRecord(Completed: false, Response: null);
            var bytes = JsonSerializer.SerializeToUtf8Bytes(rec);

            await _cache.SetAsync(Key(key), bytes, new DistributedCacheEntryOptions
            {
                AbsoluteExpirationRelativeToNow = ttl
            }, ct);

            return true;
        }

        public async Task CompleteAsync(string key, IdempotencyResponse response, TimeSpan ttl, CancellationToken ct)
        {
            var rec = new IdempotencyRecord(Completed: true, Response: response);
            var bytes = JsonSerializer.SerializeToUtf8Bytes(rec);

            await _cache.SetAsync(Key(key), bytes, new DistributedCacheEntryOptions
            {
                AbsoluteExpirationRelativeToNow = ttl
            }, ct);
        }
    }
}
