namespace MultiTenantApi.Middleware;

/// <summary>
/// Security headers are defense-in-depth. Many should also be set at the gateway/CDN.
/// This middleware avoids common classes of browser-based abuse (clickjacking, MIME sniffing).
/// </summary>
public sealed class SecurityHeadersMiddleware(RequestDelegate next)
{
    public async Task InvokeAsync(HttpContext context)
    {
        var headers = context.Response.Headers;

        headers["X-Content-Type-Options"] = "nosniff";
        headers["X-Frame-Options"] = "DENY";
        headers["Referrer-Policy"] = "no-referrer";
        headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()";
        headers["Cross-Origin-Opener-Policy"] = "same-origin";
        headers["Cross-Origin-Resource-Policy"] = "same-site";

        // For pure APIs, CSP is mostly irrelevant, but setting a safe default doesn't hurt.
        headers["Content-Security-Policy"] = "default-src 'none'; frame-ancestors 'none';";

        await next(context);
    }
}
