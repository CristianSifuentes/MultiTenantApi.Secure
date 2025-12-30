using System.Text.Json;
using Microsoft.Extensions.Caching.Distributed;


namespace MultiTenantApi.Services.JobStore
{
    public interface IJobStore
    {
        Task SetAsync(JobInfo job, TimeSpan ttl, CancellationToken ct);
        Task<JobInfo?> GetAsync(string jobId, CancellationToken ct);
    }

    public sealed class DistributedJobStore : IJobStore
    {
        private readonly IDistributedCache _cache;
        private static readonly JsonSerializerOptions JsonOpts = new(JsonSerializerDefaults.Web);

        public DistributedJobStore(IDistributedCache cache) => _cache = cache;

        public Task SetAsync(JobInfo job, TimeSpan ttl, CancellationToken ct)
        {
            var bytes = JsonSerializer.SerializeToUtf8Bytes(job, JsonOpts);
            return _cache.SetAsync(
                key: $"job:{job.JobId}",
                value: bytes,
                options: new DistributedCacheEntryOptions { AbsoluteExpirationRelativeToNow = ttl },
                token: ct);
        }

        public async Task<JobInfo?> GetAsync(string jobId, CancellationToken ct)
        {
            var bytes = await _cache.GetAsync($"job:{jobId}", ct);
            if (bytes is null) return null;
            return JsonSerializer.Deserialize<JobInfo>(bytes, JsonOpts);
        }
    }

}
