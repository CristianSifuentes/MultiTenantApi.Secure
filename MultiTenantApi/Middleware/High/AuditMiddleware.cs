using System.Diagnostics;
using System.Security.Claims;

namespace MultiTenantApi.Middleware.High;

/// <summary>
/// Minimal audit trail for API calls:
/// - Records who did what, when, where, and how long it took.
/// - Avoids logging secrets (Authorization headers, tokens, raw bodies).
/// </summary>
public sealed class AuditMiddleware(RequestDelegate next, ILogger<AuditMiddleware> logger)
{
    public async Task InvokeAsync(HttpContext context)
    {
        var sw = Stopwatch.StartNew();
        try
        {
            await next(context);
        }
        finally
        {
            sw.Stop();

            var user = context.User;
            var tid = user.FindFirstValue("tid");
            var oid = user.FindFirstValue("oid");
            var appid = user.FindFirstValue("appid") ?? user.FindFirstValue("azp");
            var correlation = context.Items.TryGetValue(CorrelationIdMiddleware.HeaderName, out var c) ? c?.ToString() : null;

            logger.LogInformation("AUDIT {StatusCode} {Method} {Path} in {ElapsedMs}ms tid={Tid} oid={Oid} appid={AppId} corr={CorrelationId}",
                context.Response.StatusCode,
                context.Request.Method,
                context.Request.Path.Value,
                sw.ElapsedMilliseconds,
                tid,
                oid,
                appid,
                correlation);
        }
    }
}
