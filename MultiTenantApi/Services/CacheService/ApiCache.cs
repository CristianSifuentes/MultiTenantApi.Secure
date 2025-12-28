using System.Text.Json;
using Microsoft.Extensions.Caching.Distributed;

namespace MultiTenantApi.Services.CacheService
{


    public interface IApiCache
    {
        Task<T?> GetAsync<T>(string key, CancellationToken ct);
        Task SetAsync<T>(string key, T value, TimeSpan ttl, CancellationToken ct);
        Task<T> GetOrCreateAsync<T>(string key, TimeSpan ttl, Func<CancellationToken, Task<T>> factory, CancellationToken ct);
    }

    public sealed class ApiCache : IApiCache
    {
        private readonly IDistributedCache _cache;
        private static readonly JsonSerializerOptions JsonOpts = new(JsonSerializerDefaults.Web);

        public ApiCache(IDistributedCache cache) => _cache = cache;

        public async Task<T?> GetAsync<T>(string key, CancellationToken ct)
        {
            var bytes = await _cache.GetAsync(key, ct);
            if (bytes is null) return default;
            return JsonSerializer.Deserialize<T>(bytes, JsonOpts);
        }

        public Task SetAsync<T>(string key, T value, TimeSpan ttl, CancellationToken ct)
        {
            var bytes = JsonSerializer.SerializeToUtf8Bytes(value, JsonOpts);
            return _cache.SetAsync(key, bytes, new DistributedCacheEntryOptions
            {
                AbsoluteExpirationRelativeToNow = ttl
            }, ct);
        }

        public async Task<T> GetOrCreateAsync<T>(string key, TimeSpan ttl, Func<CancellationToken, Task<T>> factory, CancellationToken ct)
        {
            var cached = await GetAsync<T>(key, ct);
            if (cached is not null) return cached;

            var value = await factory(ct);
            await SetAsync(key, value, ttl, ct);
            return value;
        }
    }

}
