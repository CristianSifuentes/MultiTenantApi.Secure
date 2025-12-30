using MultiTenantApi.Models;
using System.Security.Cryptography;

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
//public sealed class InMemoryRawDataService : IRawDataService
//{
//    private readonly List<RawRecord> _data;

//    public InMemoryRawDataService()
//    {
//        // Demo multi-tenant dataset (ABAC-ready)
//        var tenants = new[] { "51abcaf2-43cc-48f6-9356-dbd3236ba843", "tenant-b", "tenant-c" };

//        _data = Enumerable.Range(0, 25_000).Select(i => new RawRecord
//        {
//            InternalId = Guid.NewGuid(),
//            CreatedAt = DateTimeOffset.UtcNow.AddSeconds(-i),
//            Channel = (i % 2 == 0) ? "web" : "api",
//            Text = $"sample payload {i}",
//            UserInternalId = $"user-{i % 500}",

//            // ✅ ABAC attribute
//            TenantId = tenants[i % tenants.Length]
//        }).ToList();
//    }

//    public Task<PageResult<RawRecord>> QueryAsync(
//        string tenantId,
//        string? filter,
//        string? nextToken,
//        int take,
//        CancellationToken ct)
//    {
//        if (string.IsNullOrWhiteSpace(tenantId))
//            throw new ArgumentException("tenantId is required.", nameof(tenantId));

//        // nextToken is an index cursor for this in-memory demo.
//        var offset = 0;
//        if (!string.IsNullOrWhiteSpace(nextToken) &&
//            int.TryParse(nextToken, out var parsed) &&
//            parsed >= 0)
//        {
//            offset = parsed;
//        }

//        // ✅ ABAC enforcement: tenant scoping FIRST
//        IEnumerable<RawRecord> q = _data.Where(r => r.TenantId == tenantId);

//        // Optional filter (still within tenant boundary)
//        if (!string.IsNullOrWhiteSpace(filter))
//        {
//            var f = filter.Trim();
//            q = q.Where(r =>
//                r.Text.Contains(f, StringComparison.OrdinalIgnoreCase) ||
//                r.Channel.Contains(f, StringComparison.OrdinalIgnoreCase));
//        }

//        // Materialize once to avoid multiple enumeration.
//        var list = q as IList<RawRecord> ?? q.ToList();

//        var page = list.Skip(offset).Take(take).ToList();
//        var next = (offset + page.Count) < list.Count ? (offset + page.Count).ToString() : null;

//        return Task.FromResult(new PageResult<RawRecord>(page, next));
//    }


//    public Task<PageResult<RawRecord>> SearchAsync(
//    string tenantId,
//    string query,
//    string[]? channels,
//    DateTimeOffset? fromUtc,
//    DateTimeOffset? toUtc,
//    string? nextToken,
//    int take,
//    CancellationToken ct)
//    {
//        if (string.IsNullOrWhiteSpace(tenantId))
//            throw new ArgumentException("tenantId is required.", nameof(tenantId));

//        if (string.IsNullOrWhiteSpace(query))
//            throw new ArgumentException("query is required.", nameof(query));

//        // Cursor (demo offset)
//        var offset = 0;
//        if (!string.IsNullOrWhiteSpace(nextToken) &&
//            int.TryParse(nextToken, out var parsed) && parsed >= 0)
//        {
//            offset = parsed;
//        }

//        // ✅ ABAC boundary FIRST: tenant scope
//        IEnumerable<RawRecord> q = _data.Where(r => r.TenantId == tenantId);

//        // Optional channel filter (whitelisted by validator)
//        if (channels is { Length: > 0 })
//        {
//            var allowed = new HashSet<string>(channels, StringComparer.OrdinalIgnoreCase);
//            q = q.Where(r => allowed.Contains(r.Channel));
//        }

//        // Optional time bounding
//        if (fromUtc.HasValue) q = q.Where(r => r.CreatedAt >= fromUtc.Value);
//        if (toUtc.HasValue) q = q.Where(r => r.CreatedAt <= toUtc.Value);

//        // Search match (within tenant)
//        var term = query.Trim();
//        q = q.Where(r => r.Text.Contains(term, StringComparison.OrdinalIgnoreCase));

//        // Materialize once
//        var list = q as IList<RawRecord> ?? q.ToList();

//        var page = list.Skip(offset).Take(take).ToList();
//        var next = (offset + page.Count) < list.Count ? (offset + page.Count).ToString() : null;

//        return Task.FromResult(new PageResult<RawRecord>(page, next));
//    }


//}




public sealed class InMemoryRawDataService : IRawDataService
{
    private readonly List<RawRecord> _data;

    public InMemoryRawDataService()
    {
        // Demo multi-tenant dataset (ABAC-ready)
        var tenants = new[] { "51abcaf2-43cc-48f6-9356-dbd3236ba843", "tenant-b", "tenant-c" };

        // Pools para simular datos
        var skills = new[] { "", "Spanish", "English", "Billing", "Support" };
        var directions = new[] { "Inbound", "Outbound" };

        // Nombres ejemplo para alias (luego los enmascaramos)
        var agents = new[]
        {
            "John Doe",
            "Juan Sifuentes",
            "Quinn Parker",
            "Maria Lopez",
            "Jade Smith"
        };
        
        var now = DateTimeOffset.UtcNow;

        _data = Enumerable.Range(0, 25_000).Select(i =>
        {
            var tenantId = tenants[i % tenants.Length];
            var endTime = now.AddSeconds(-i);

            // Tipos que quieres ver (Missed/Abandoned) y algunos Answered
            var kindRoll = i % 10; // determinístico (sin Random) para demo
            var type =
                kindRoll < 5 ? "Missed" :
                kindRoll < 9 ? "Abandoned" :
                "Answered";

            var accepted = type == "Answered";
            var missed = type == "Missed";
            var abandoned = type == "Abandoned";

            // Duraciones
            var queueTime = abandoned ? 30.0 : 19.03;   // igual a tu ejemplo
            var talkTime = accepted ? 120.0 : 0.0;      // si Answered, algo > 0
            var callTime = queueTime + talkTime;

            // Skill
            var skill = skills[(i / 3) % skills.Length];

            // Alias (masked)
            var answeredBy = accepted ? MaskAlias(agents[i % agents.Length]) : null;
            var notHandledBy = (missed || abandoned) ? MaskAlias(agents[(i + 1) % agents.Length]) : null;

            // Caller number masked: last 4 “semi-real”
            var last4 = (1000 + (i % 9000)).ToString(); // 1000-9999
            var callerMasked = MaskPhoneLast4(last4);

            var internalId = Guid.NewGuid();
            var syntheticId = RawRecord.MakeSyntheticCallId(internalId, tenantId, endTime);

            return new RawRecord
            {
                InternalId = internalId,
                TenantId = tenantId,

                SyntheticCallId = syntheticId,
                CallDirection = directions[i % directions.Length],
                Type = type,

                Accepted = accepted,
                Missed = missed,
                Abandoned = abandoned,

                EndTime = endTime,
                QueueTime = queueTime,
                TalkTime = talkTime,
                CallTime = callTime,

                Skill = skill,

                AnsweredByAlias = answeredBy,
                NotHandledByAlias = notHandledBy,

                CallerNumberMasked = callerMasked,

                // Internos (si quieres conservarlos)
                CreatedAt = endTime,
                Channel = (i % 2 == 0) ? "web" : "api",
                Text = $"synthetic call record {i}",
                UserInternalId = $"user-{i % 500}"
            };
        }).ToList();
    }

    // ======= masking helpers =======

    private static string MaskAlias(string fullName)
    {
        // "John Doe" => "J*** D**"
        var parts = fullName.Split(' ', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
        if (parts.Length == 0) return "****";

        static string MaskWord(string w)
        {
            if (w.Length <= 1) return "*";
            if (w.Length == 2) return $"{w[0]}*";
            return $"{w[0]}***{w[^1]}";
        }

        if (parts.Length == 1) return MaskWord(parts[0]);

        // Para que se parezca más a tu ejemplo: primer nombre con *** y último con ** (más corto)
        var first = parts[0];
        var last = parts[^1];

        var firstMasked = first.Length <= 1 ? "*" : $"{first[0]}***";
        var lastMasked = last.Length <= 2 ? $"{last[0]}*" : $"{last[0]}**";

        return $"{firstMasked} {lastMasked}";
    }

    private static string MaskPhoneLast4(string last4)
        => $"********{last4}";



    //public Task<PageResult<RawRecord>> QueryAsync(
    //    string tenantId,
    //    string? filter,
    //    string? nextToken,
    //    int take,
    //    CancellationToken ct)
    //{
    //    if (string.IsNullOrWhiteSpace(tenantId))
    //        throw new ArgumentException("tenantId is required.", nameof(tenantId));

    //    // nextToken is an index cursor for this in-memory demo.
    //    var offset = 0;
    //    if (!string.IsNullOrWhiteSpace(nextToken) &&
    //        int.TryParse(nextToken, out var parsed) &&
    //        parsed >= 0)
    //    {
    //        offset = parsed;
    //    }

    //    // ✅ ABAC enforcement: tenant scoping FIRST
    //    IEnumerable<RawRecord> q = _data.Where(r => r.TenantId == tenantId);

    //    // Optional filter (still within tenant boundary)
    //    if (!string.IsNullOrWhiteSpace(filter))
    //    {
    //        var f = filter.Trim();
    //        q = q.Where(r =>
    //            r.Text.Contains(f, StringComparison.OrdinalIgnoreCase) ||
    //            r.Channel.Contains(f, StringComparison.OrdinalIgnoreCase));
    //    }

    //    // Materialize once to avoid multiple enumeration.
    //    var list = q as IList<RawRecord> ?? q.ToList();

    //    var page = list.Skip(offset).Take(take).ToList();
    //    var next = (offset + page.Count) < list.Count ? (offset + page.Count).ToString() : null;

    //    return Task.FromResult(new PageResult<RawRecord>(page, next));
    //}

    public Task<PageResult<RawRecord>> QueryAsync(
   string tenantId,
   string? filter,
   string? nextToken,
   int take,
   CancellationToken ct)
    {
        if (string.IsNullOrWhiteSpace(tenantId))
            throw new ArgumentException("tenantId is required.", nameof(tenantId));

        var offset = 0;
        if (!string.IsNullOrWhiteSpace(nextToken) && int.TryParse(nextToken, out var parsed) && parsed >= 0)
            offset = parsed;

        IEnumerable<RawRecord> q = _data.Where(r => r.TenantId == tenantId);

        if (!string.IsNullOrWhiteSpace(filter))
        {
            var f = filter.Trim();
            q = q.Where(r =>
                r.SyntheticCallId.Contains(f, StringComparison.OrdinalIgnoreCase) ||
                r.CallDirection.Contains(f, StringComparison.OrdinalIgnoreCase) ||
                r.Type.Contains(f, StringComparison.OrdinalIgnoreCase) ||
                r.Skill.Contains(f, StringComparison.OrdinalIgnoreCase) ||
                (r.AnsweredByAlias ?? "").Contains(f, StringComparison.OrdinalIgnoreCase) ||
                (r.NotHandledByAlias ?? "").Contains(f, StringComparison.OrdinalIgnoreCase) ||
                r.CallerNumberMasked.Contains(f, StringComparison.OrdinalIgnoreCase));
        }

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

        var offset = 0;
        if (!string.IsNullOrWhiteSpace(nextToken) && int.TryParse(nextToken, out var parsed) && parsed >= 0)
            offset = parsed;

        IEnumerable<RawRecord> q = _data.Where(r => r.TenantId == tenantId);

        if (channels is { Length: > 0 })
        {
            var allowed = new HashSet<string>(channels, StringComparer.OrdinalIgnoreCase);
            q = q.Where(r => allowed.Contains(r.Channel)); // Channel sigue existiendo interno
        }

        if (fromUtc.HasValue) q = q.Where(r => r.EndTime >= fromUtc.Value);
        if (toUtc.HasValue) q = q.Where(r => r.EndTime <= toUtc.Value);

        var term = query.Trim();
        q = q.Where(r =>
            r.SyntheticCallId.Contains(term, StringComparison.OrdinalIgnoreCase) ||
            r.CallDirection.Contains(term, StringComparison.OrdinalIgnoreCase) ||
            r.Type.Contains(term, StringComparison.OrdinalIgnoreCase) ||
            r.Skill.Contains(term, StringComparison.OrdinalIgnoreCase) ||
            (r.AnsweredByAlias ?? "").Contains(term, StringComparison.OrdinalIgnoreCase) ||
            (r.NotHandledByAlias ?? "").Contains(term, StringComparison.OrdinalIgnoreCase) ||
            r.CallerNumberMasked.Contains(term, StringComparison.OrdinalIgnoreCase));

        var list = q as IList<RawRecord> ?? q.ToList();
        var page = list.Skip(offset).Take(take).ToList();
        var next = (offset + page.Count) < list.Count ? (offset + page.Count).ToString() : null;

        return Task.FromResult(new PageResult<RawRecord>(page, next));
    }



    //public Task<PageResult<RawRecord>> SearchAsync(
    //string tenantId,
    //string query,
    //string[]? channels,
    //DateTimeOffset? fromUtc,
    //DateTimeOffset? toUtc,
    //string? nextToken,
    //int take,
    //CancellationToken ct)
    //{
    //    if (string.IsNullOrWhiteSpace(tenantId))
    //        throw new ArgumentException("tenantId is required.", nameof(tenantId));

    //    if (string.IsNullOrWhiteSpace(query))
    //        throw new ArgumentException("query is required.", nameof(query));

    //    // Cursor (demo offset)
    //    var offset = 0;
    //    if (!string.IsNullOrWhiteSpace(nextToken) &&
    //        int.TryParse(nextToken, out var parsed) && parsed >= 0)
    //    {
    //        offset = parsed;
    //    }

    //    // ✅ ABAC boundary FIRST: tenant scope
    //    IEnumerable<RawRecord> q = _data.Where(r => r.TenantId == tenantId);

    //    // Optional channel filter (whitelisted by validator)
    //    if (channels is { Length: > 0 })
    //    {
    //        var allowed = new HashSet<string>(channels, StringComparer.OrdinalIgnoreCase);
    //        q = q.Where(r => allowed.Contains(r.Channel));
    //    }

    //    // Optional time bounding
    //    if (fromUtc.HasValue) q = q.Where(r => r.CreatedAt >= fromUtc.Value);
    //    if (toUtc.HasValue) q = q.Where(r => r.CreatedAt <= toUtc.Value);

    //    // Search match (within tenant)
    //    var term = query.Trim();
    //    q = q.Where(r => r.Text.Contains(term, StringComparison.OrdinalIgnoreCase));

    //    // Materialize once
    //    var list = q as IList<RawRecord> ?? q.ToList();

    //    var page = list.Skip(offset).Take(take).ToList();
    //    var next = (offset + page.Count) < list.Count ? (offset + page.Count).ToString() : null;

    //    return Task.FromResult(new PageResult<RawRecord>(page, next));
    //}

    // ======= tu QueryAsync / SearchAsync pueden quedarse igual (ABAC-first) =======
    // Solo recuerda que tu filter/search ya no debería depender de Text/Channel
    // si ahora estás devolviendo calls.
    // Te dejo versiones recomendadas abajo 👇
}

























