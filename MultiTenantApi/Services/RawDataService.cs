using MultiTenantApi.Models;

namespace MultiTenantApi.Services;

public interface IRawDataService
{
    //Task<PageResult<RawRecord>> QueryAsync(string? filter, string? nextToken, int take, CancellationToken ct);

    // ✅ ABAC : tenant scoping

     Task<PageResult<RawRecord>> QueryAsync(
          string tenantId,
          string? filter,
          string? nextToken,
          int take,
          CancellationToken ct);

        Task<PageResult<RawRecord>> SearchAsync(
        string tenantId,
        string query,
        string[]? channels,
        DateTimeOffset? fromUtc,
        DateTimeOffset? toUtc,
        string? nextToken,
        int take,
        CancellationToken ct);


}

//before ABAC
//public sealed class InMemoryRawDataService : IRawDataService
//{
//    private readonly List<RawRecord> _data;

//    public InMemoryRawDataService()
//    {
//        // Demo dataset (in production you'd query a DB with proper indexes + keyset pagination)
//        _data = Enumerable.Range(0, 25_000).Select(i => new RawRecord
//        {
//            InternalId = Guid.NewGuid(),
//            CreatedAt = DateTimeOffset.UtcNow.AddSeconds(-i),
//            Channel = (i % 2 == 0) ? "web" : "api",
//            Text = $"sample payload {i}",
//            UserInternalId = $"user-{i % 500}"
//        }).ToList();
//    }

//    public Task<PageResult<RawRecord>> QueryAsync(string? filter, string? nextToken, int take, CancellationToken ct)
//    {
//        // nextToken is an index cursor for this in-memory demo.
//        var offset = 0;
//        if (!string.IsNullOrWhiteSpace(nextToken) && int.TryParse(nextToken, out var parsed) && parsed >= 0)
//            offset = parsed;

//        IEnumerable<RawRecord> q = _data;

//        if (!string.IsNullOrWhiteSpace(filter))
//        {
//            var f = filter.Trim();
//            q = q.Where(r => r.Text.Contains(f, StringComparison.OrdinalIgnoreCase) ||
//                             r.Channel.Contains(f, StringComparison.OrdinalIgnoreCase));
//        }

//        // Materialize once to avoid multiple enumeration.
//        var list = q as IList<RawRecord> ?? q.ToList();

//        var page = list.Skip(offset).Take(take).ToList();
//        var next = (offset + page.Count) < list.Count ? (offset + page.Count).ToString() : null;

//        return Task.FromResult(new PageResult<RawRecord>(page, next));
//    }
//}

// after aba


// after
public sealed class InMemoryRawDataService : IRawDataService
{
    private readonly List<RawRecord> _data;

    public InMemoryRawDataService()
    {
        // Demo multi-tenant dataset (ABAC-ready)
        var tenants = new[] { "tenant-a", "tenant-b", "tenant-c" };

        _data = Enumerable.Range(0, 25_000).Select(i => new RawRecord
        {
            InternalId = Guid.NewGuid(),
            CreatedAt = DateTimeOffset.UtcNow.AddSeconds(-i),
            Channel = (i % 2 == 0) ? "web" : "api",
            Text = $"sample payload {i}",
            UserInternalId = $"user-{i % 500}",

            // ✅ ABAC attribute
            TenantId = tenants[i % tenants.Length]
        }).ToList();
    }

    public Task<PageResult<RawRecord>> QueryAsync(
        string tenantId,
        string? filter,
        string? nextToken,
        int take,
        CancellationToken ct)
    {
        if (string.IsNullOrWhiteSpace(tenantId))
            throw new ArgumentException("tenantId is required.", nameof(tenantId));

        // nextToken is an index cursor for this in-memory demo.
        var offset = 0;
        if (!string.IsNullOrWhiteSpace(nextToken) &&
            int.TryParse(nextToken, out var parsed) &&
            parsed >= 0)
        {
            offset = parsed;
        }

        // ✅ ABAC enforcement: tenant scoping FIRST
        IEnumerable<RawRecord> q = _data.Where(r => r.TenantId == tenantId);

        // Optional filter (still within tenant boundary)
        if (!string.IsNullOrWhiteSpace(filter))
        {
            var f = filter.Trim();
            q = q.Where(r =>
                r.Text.Contains(f, StringComparison.OrdinalIgnoreCase) ||
                r.Channel.Contains(f, StringComparison.OrdinalIgnoreCase));
        }

        // Materialize once to avoid multiple enumeration.
        var list = q as IList<RawRecord> ?? q.ToList();

        var page = list.Skip(offset).Take(take).ToList();
        var next = (offset + page.Count) < list.Count ? (offset + page.Count).ToString() : null;

        return Task.FromResult(new PageResult<RawRecord>(page, next));
    }


    public Task<PageResult<RawRecord>> SearchAsync(
    string tenantId,
    string query,
    string[]? channels,
    DateTimeOffset? fromUtc,
    DateTimeOffset? toUtc,
    string? nextToken,
    int take,
    CancellationToken ct)
    {
        if (string.IsNullOrWhiteSpace(tenantId))
            throw new ArgumentException("tenantId is required.", nameof(tenantId));

        if (string.IsNullOrWhiteSpace(query))
            throw new ArgumentException("query is required.", nameof(query));

        // Cursor (demo offset)
        var offset = 0;
        if (!string.IsNullOrWhiteSpace(nextToken) &&
            int.TryParse(nextToken, out var parsed) && parsed >= 0)
        {
            offset = parsed;
        }

        // ✅ ABAC boundary FIRST: tenant scope
        IEnumerable<RawRecord> q = _data.Where(r => r.TenantId == tenantId);

        // Optional channel filter (whitelisted by validator)
        if (channels is { Length: > 0 })
        {
            var allowed = new HashSet<string>(channels, StringComparer.OrdinalIgnoreCase);
            q = q.Where(r => allowed.Contains(r.Channel));
        }

        // Optional time bounding
        if (fromUtc.HasValue) q = q.Where(r => r.CreatedAt >= fromUtc.Value);
        if (toUtc.HasValue) q = q.Where(r => r.CreatedAt <= toUtc.Value);

        // Search match (within tenant)
        var term = query.Trim();
        q = q.Where(r => r.Text.Contains(term, StringComparison.OrdinalIgnoreCase));

        // Materialize once
        var list = q as IList<RawRecord> ?? q.ToList();

        var page = list.Skip(offset).Take(take).ToList();
        var next = (offset + page.Count) < list.Count ? (offset + page.Count).ToString() : null;

        return Task.FromResult(new PageResult<RawRecord>(page, next));
    }


}