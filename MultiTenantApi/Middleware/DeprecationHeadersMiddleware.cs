using Microsoft.Extensions.Options;

namespace MultiTenantApi.Middleware
{
    public sealed class DeprecationPolicyOptions
    {
        public bool EnableV1DeprecationHeaders { get; init; } = true;
        public DateTimeOffset? V1SunsetUtc { get; init; }
        public string? DeprecationDocUrl { get; init; }
    }

    public sealed class DeprecationHeadersMiddleware : IMiddleware
    {
        private readonly IOptions<DeprecationPolicyOptions> _opt;

        public DeprecationHeadersMiddleware(IOptions<DeprecationPolicyOptions> opt) => _opt = opt;

        public async Task InvokeAsync(HttpContext ctx, RequestDelegate next)
        {
            await next(ctx);

            // Decide versión por ruta (URL strategy)
            var path = ctx.Request.Path.Value ?? "";
            var isV1 = path.StartsWith("/api/v1", StringComparison.OrdinalIgnoreCase);

            // o por header strategy:
            // var apiVersion = (ctx.Items["api_version"] as string) ?? "1";
            // var isV1 = apiVersion == "1";

            if (!isV1) return;

            var opt = _opt.Value;
            if (!opt.EnableV1DeprecationHeaders) return;

            ctx.Response.Headers["Deprecation"] = "true";

            if (opt.V1SunsetUtc is not null)
                ctx.Response.Headers["Sunset"] = opt.V1SunsetUtc.Value.ToString("R");

            if (!string.IsNullOrWhiteSpace(opt.DeprecationDocUrl))
                ctx.Response.Headers["Link"] = $"<{opt.DeprecationDocUrl}>; rel=\"deprecation\"";

            ctx.Response.Headers["Warning"] =
                "299 - \"API v1 is deprecated; migrate to v2\"";
        }
    }

}
