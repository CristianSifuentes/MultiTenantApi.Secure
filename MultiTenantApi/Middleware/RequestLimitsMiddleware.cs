using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Options;
using System.Reflection.PortableExecutable;

namespace MultiTenantApi.Middleware;



//4.1 RequestLimitsMiddleware(bloquea payloads enormes / headers sospechosos)
public sealed class RequestLimitsOptions
{
    public long MaxBodyBytes { get; set; } = 1_048_576; // 1 MB default
    public int MaxQueryStringLength { get; set; } = 2048;
    public int MaxHeaderValueLength { get; set; } = 4096;
    public string[] AllowedContentTypes { get; set; } = ["application/json"];
}

public sealed class RequestLimitsMiddleware : IMiddleware
{
    private readonly IOptions<RequestLimitsOptions> _opt;

    public RequestLimitsMiddleware(IOptions<RequestLimitsOptions> opt) => _opt = opt;

    public async Task InvokeAsync(HttpContext ctx, RequestDelegate next)
    {
        var o = _opt.Value;

        // Querystring too big => cheap reject (common WAF-style)
        if (ctx.Request.QueryString.HasValue &&
            ctx.Request.QueryString.Value!.Length > o.MaxQueryStringLength)
        {
            ctx.Response.StatusCode = StatusCodes.Status414UriTooLong;
            await ctx.Response.WriteAsJsonAsync(new { error = "uri_too_long" });
            return;
        }

        // Body size limit (protect Kestrel + app)
        // Only applies if Content-Length known; still valuable.
        if (ctx.Request.ContentLength.HasValue && ctx.Request.ContentLength.Value > o.MaxBodyBytes)
        {
            ctx.Response.StatusCode = StatusCodes.Status413PayloadTooLarge;
            await ctx.Response.WriteAsJsonAsync(new { error = "payload_too_large" });
            return;
        }

        // Content-Type enforcement for body methods
        if (HttpMethods.IsPost(ctx.Request.Method) || HttpMethods.IsPut(ctx.Request.Method) || HttpMethods.IsPatch(ctx.Request.Method))
        {
            var ct = ctx.Request.ContentType ?? "";
            var allowed = o.AllowedContentTypes.Any(a => ct.StartsWith(a, StringComparison.OrdinalIgnoreCase));
            if (!allowed)
            {
                ctx.Response.StatusCode = StatusCodes.Status415UnsupportedMediaType;
                await ctx.Response.WriteAsJsonAsync(new { error = "unsupported_media_type" });
                return;
            }
        }

        // Basic header sanity (avoid absurd header bombing)
        foreach (var h in ctx.Request.Headers)
        {
            if (h.Value.Count == 0) continue;
            if (h.Value.ToString().Length > o.MaxHeaderValueLength)
            {
                ctx.Response.StatusCode = StatusCodes.Status400BadRequest;
                await ctx.Response.WriteAsJsonAsync(new { error = "bad_request" });
                return;
            }
        }

        await next(ctx);
    }
}
