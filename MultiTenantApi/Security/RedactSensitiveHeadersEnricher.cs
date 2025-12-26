using Serilog.Core;
using Serilog.Events;
using Microsoft.AspNetCore.Http;

namespace MultiTenantApi.Security
{
    public sealed class RedactSensitiveHeadersEnricher : ILogEventEnricher
    {
        private readonly IHttpContextAccessor _http;

        private static readonly HashSet<string> SensitiveHeaders = new(StringComparer.OrdinalIgnoreCase)
    {
        "Authorization", "Cookie", "Set-Cookie", "X-Api-Key"
    };

    public RedactSensitiveHeadersEnricher(IHttpContextAccessor http) => _http = http;

    public void Enrich(LogEvent logEvent, ILogEventPropertyFactory pf)
    {
            var ctx = _http.HttpContext;
            if (ctx is null) return;

            // Only attach minimal safe telemetry
            logEvent.AddOrUpdateProperty(pf.CreateProperty("TraceId", ctx.TraceIdentifier));
            logEvent.AddOrUpdateProperty(pf.CreateProperty("Path", ctx.Request.Path.Value));

            // If you *must* attach headers, do it safely:
            var safeHeaders = ctx.Request.Headers
                .Where(h => !SensitiveHeaders.Contains(h.Key))
                .ToDictionary(h => h.Key, h => (object?)h.Value.ToString());

            logEvent.AddOrUpdateProperty(pf.CreateProperty("HeadersSafe", safeHeaders, destructureObjects: true));
        }
    }
}
