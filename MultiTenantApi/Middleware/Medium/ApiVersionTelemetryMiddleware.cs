using System.Security.Claims;

namespace MultiTenantApi.Middleware.Medium
{
    public sealed class ApiVersionTelemetryMiddleware : IMiddleware
    {
        private readonly ILogger<ApiVersionTelemetryMiddleware> _log;

        public ApiVersionTelemetryMiddleware(ILogger<ApiVersionTelemetryMiddleware> log) => _log = log;

        public async Task InvokeAsync(HttpContext ctx, RequestDelegate next)
        {
            await next(ctx);

            var path = ctx.Request.Path.Value ?? "";
            var version = path.StartsWith("/api/v2", StringComparison.OrdinalIgnoreCase) ? "2" :
                          path.StartsWith("/api/v1", StringComparison.OrdinalIgnoreCase) ? "1" : "unversioned";

            var tid = ctx.User?.FindFirstValue("tid");
            var azp = ctx.User?.FindFirstValue("azp") ?? ctx.User?.FindFirstValue("appid");

            _log.LogInformation("api_version_usage version={Version} tid={Tid} client={Client} path={Path} status={Status}",
                version, tid ?? "n/a", azp ?? "n/a", path, ctx.Response.StatusCode);
        }
    }

}
