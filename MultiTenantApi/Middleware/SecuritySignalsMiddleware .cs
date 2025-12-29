using System.Security.Claims;

namespace MultiTenantApi.Middleware
{
    public sealed class SecuritySignalsMiddleware : IMiddleware
    {
        private static readonly System.Diagnostics.Metrics.Meter Meter = new("MultiTenantApi.Security");
        private static readonly System.Diagnostics.Metrics.Counter<long> AuthFailures =
            Meter.CreateCounter<long>("auth_failures_total");
        private static readonly System.Diagnostics.Metrics.Counter<long> RateLimitHits =
            Meter.CreateCounter<long>("rate_limit_hits_total");
        private static readonly System.Diagnostics.Metrics.Histogram<double> RequestLatencyMs =
            Meter.CreateHistogram<double>("request_latency_ms");

        private readonly Serilog.ILogger _log;

        public SecuritySignalsMiddleware(Serilog.ILogger log) => _log = log;

        public async Task InvokeAsync(HttpContext ctx, RequestDelegate next)
        {
            var sw = System.Diagnostics.Stopwatch.StartNew();

            await next(ctx);

            sw.Stop();

            var path = ctx.Request.Path.Value ?? "/";
            var status = ctx.Response.StatusCode;

            var tenant = ctx.User?.FindFirstValue("tid") ?? "anonymous";
            var client = ctx.User?.FindFirstValue("azp") ?? ctx.User?.FindFirstValue("appid") ?? "anonymous";

            RequestLatencyMs.Record(sw.Elapsed.TotalMilliseconds,
                KeyValuePair.Create<string, object?>("path", path),
                KeyValuePair.Create<string, object?>("status", status),
                KeyValuePair.Create<string, object?>("tenant", tenant),
                KeyValuePair.Create<string, object?>("client", client));

            if (status is 401 or 403)
            {
                AuthFailures.Add(1,
                    KeyValuePair.Create<string, object?>("path", path),
                    KeyValuePair.Create<string, object?>("tenant", tenant),
                    KeyValuePair.Create<string, object?>("client", client));

                _log.Warning("Auth failure {Status} {Path} tenant={Tenant} client={Client}",
                    status, path, tenant, client);
            }

            if (status == StatusCodes.Status429TooManyRequests)
            {
                RateLimitHits.Add(1,
                    KeyValuePair.Create<string, object?>("path", path),
                    KeyValuePair.Create<string, object?>("tenant", tenant),
                    KeyValuePair.Create<string, object?>("client", client));

                _log.Warning("Rate limit hit {Path} tenant={Tenant} client={Client}",
                    path, tenant, client);
            }
        }
    }

}
