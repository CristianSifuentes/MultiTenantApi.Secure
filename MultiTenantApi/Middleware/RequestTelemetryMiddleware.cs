namespace MultiTenantApi.Middleware
{
    using System.Diagnostics;
    using Serilog.Context;

    public sealed class RequestTelemetryMiddleware : IMiddleware
    {
        private static readonly HashSet<string> SensitiveHeaders = new(StringComparer.OrdinalIgnoreCase)
        {
            "Authorization", "Cookie", "Set-Cookie", "X-Api-Key"
        };

        private readonly ILogger<RequestTelemetryMiddleware> _log;

        public RequestTelemetryMiddleware(ILogger<RequestTelemetryMiddleware> log) => _log = log;

        public async Task InvokeAsync(HttpContext ctx, RequestDelegate next)
        {
            var sw = Stopwatch.StartNew();

            // Básicos
            var method = ctx.Request.Method;
            var path = ctx.Request.Path.Value ?? "/";
            var route = ctx.GetEndpoint()?.DisplayName ?? "unknown";

            // Identidad (NO PII)
            var tid = ctx.User?.FindFirst("tid")?.Value;
            var clientAppId = ctx.User?.FindFirst("azp")?.Value ?? ctx.User?.FindFirst("appid")?.Value;

            // IP / forwarded (útil para seguridad)
            var ip = ctx.Connection.RemoteIpAddress?.ToString();
            var fwd = ctx.Request.Headers["X-Forwarded-For"].ToString();
            var proto = ctx.Request.Headers["X-Forwarded-Proto"].ToString();

            // Razón auth-fail (sin detalles sensibles)
            string? authFailReason = null;

            try
            {
                await next(ctx);
            }
            catch (Exception ex)
            {
                authFailReason = ctx.Items.TryGetValue("auth_fail_reason", out var r) ? r?.ToString() : null;

                _log.LogError(ex,
                    "request_failed method={Method} path={Path} route={Route} tid={Tid} client={Client} status=500 elapsed_ms={Elapsed}",
                    method, path, route, tid ?? "n/a", clientAppId ?? "n/a", sw.ElapsedMilliseconds);

                throw;
            }
            finally
            {
                sw.Stop();

                var status = ctx.Response.StatusCode;
                authFailReason ??= ctx.Items.TryGetValue("auth_fail_reason", out var r) ? r?.ToString() : null;

                using (LogContext.PushProperty("http_method", method))
                using (LogContext.PushProperty("path", path))
                using (LogContext.PushProperty("route", route))
                using (LogContext.PushProperty("status", status))
                using (LogContext.PushProperty("elapsed_ms", sw.ElapsedMilliseconds))
                using (LogContext.PushProperty("tenant_id", tid ?? "n/a"))
                using (LogContext.PushProperty("client_id", clientAppId ?? "n/a"))
                using (LogContext.PushProperty("ip", ip ?? "n/a"))
                using (LogContext.PushProperty("forwarded_for", string.IsNullOrWhiteSpace(fwd) ? "n/a" : fwd))
                using (LogContext.PushProperty("forwarded_proto", string.IsNullOrWhiteSpace(proto) ? "n/a" : proto))
                using (LogContext.PushProperty("auth_fail_reason", authFailReason ?? "n/a"))
                {
                    // ✅ Un log por request, fácil de query en SIEM / AppInsights / ELK
                    _log.LogInformation("request_completed");
                }
            }
        }
    }

}
