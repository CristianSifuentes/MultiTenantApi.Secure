namespace MultiTenantApi.Middleware;

/// <summary>
/// Enforces HTTPS. Also respects X-Forwarded-Proto when running behind a proxy/gateway.
/// </summary>
public sealed class EnforceHttpsMiddleware(RequestDelegate next, ILogger<EnforceHttpsMiddleware> logger)
{
    public async Task InvokeAsync(HttpContext context)
    {
        // If behind reverse proxy, X-Forwarded-Proto indicates original scheme.
        var forwardedProto = context.Request.Headers["X-Forwarded-Proto"].ToString();
        var isHttps = context.Request.IsHttps || string.Equals(forwardedProto, "https", StringComparison.OrdinalIgnoreCase);

        if (!isHttps)
        {
            // Avoid leaking host details in logs beyond what's necessary.
            logger.LogWarning("Rejected non-HTTPS request: {Method} {Path}", context.Request.Method, context.Request.Path);

            var host = context.Request.Host;
            var path = context.Request.Path + context.Request.QueryString;
            var httpsUrl = $"https://{host}{path}";

            // 307 preserves method semantics (important for POST/PUT).
            context.Response.Redirect(httpsUrl, permanent: false);
            return;
        }

        await next(context);
    }
}
