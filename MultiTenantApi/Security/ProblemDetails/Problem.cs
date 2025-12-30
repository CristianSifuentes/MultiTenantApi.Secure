using System.Security.Claims;

namespace MultiTenantApi.Security.ProblemDetails
{
    public static class ApiErrorCodes
    {
        public const string InvalidRequest = "invalid_request";
        public const string Unauthorized = "unauthorized";
        public const string Forbidden = "forbidden";
        public const string NotFound = "not_found";
        public const string Conflict = "conflict";
        public const string RateLimited = "rate_limited";
        public const string Unexpected = "unexpected_error";
    }


    public static class Problem
    {
        public static IResult Create(
            HttpContext ctx,
            int status,
            string code,
            string title,
            string? detail = null,
            IDictionary<string, object?>? extra = null)
        {
            var ext = new Dictionary<string, object?>
            {
                ["errorCode"] = code,
                ["traceId"] = ctx.TraceIdentifier
            };

            // Correlation ID (si tu middleware lo mete en Items)
            if (ctx.Items.TryGetValue("correlation_id", out var cid) && cid is string s && !string.IsNullOrWhiteSpace(s))
                ext["correlationId"] = s;

            // Tenant context si lo tienes disponible (sin filtrar secretos)
            var tid = ctx.User?.FindFirstValue("tid");
            if (!string.IsNullOrWhiteSpace(tid))
                ext["tenantId"] = tid;

            if (extra is not null)
                foreach (var kv in extra) ext[kv.Key] = kv.Value;

            return Results.Problem(
                title: title,
                detail: detail, // ⚠️ aquí NO metas stacktrace nunca
                statusCode: status,
                extensions: ext);
        }
    }

}
