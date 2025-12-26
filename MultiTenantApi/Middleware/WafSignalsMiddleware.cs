using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using System.Text.RegularExpressions;

namespace MultiTenantApi.Middleware;

public sealed class WafSignalsMiddleware : IMiddleware
{
    private readonly ILogger<WafSignalsMiddleware> _log;

    // Very conservative patterns — DO NOT rely on this for security, it’s signals + optional block.
    private static readonly Regex SuspiciousPath =
        new(@"(\.\./|%2e%2e%2f|%2e%2e\\|<script|%3cscript|union\s+select|sleep\(|benchmark\()",
            RegexOptions.IgnoreCase | RegexOptions.Compiled);

    public WafSignalsMiddleware(ILogger<WafSignalsMiddleware> log) => _log = log;

    public async Task InvokeAsync(HttpContext ctx, RequestDelegate next)
    {
        var score = 0;

        var path = ctx.Request.Path.Value ?? "";
        var qs = ctx.Request.QueryString.Value ?? "";
        var ua = ctx.Request.Headers.UserAgent.ToString();

        if (SuspiciousPath.IsMatch(path) || SuspiciousPath.IsMatch(qs))
            score += 5;

        if (!string.IsNullOrWhiteSpace(ua) && ua.Length < 8) // tiny UA often bots
            score += 2;

        if (ctx.Request.Headers.TryGetValue("X-Forwarded-For", out var xff) && xff.ToString().Length > 512)
            score += 2;

        // Attach signals for later middlewares / logging
        ctx.Items["waf_score"] = score;

        // Log only when suspicious (avoid noisy logs)
        if (score >= 5)
        {
            _log.LogWarning("WAF-SIGNAL score={Score} path={Path} qs_len={QsLen} ua={UA}",
                score, path, qs.Length, ua);
        }

        // Optional: hard block only at high score (be careful with false positives)
        if (score >= 10)
        {
            ctx.Response.StatusCode = StatusCodes.Status400BadRequest;
            await ctx.Response.WriteAsJsonAsync(new { error = "suspicious_request" });
            return;
        }

        await next(ctx);
    }
}
