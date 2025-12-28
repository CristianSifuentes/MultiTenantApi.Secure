namespace MultiTenantApi.Middleware
{
    public sealed class ApiVersioningMiddleware : IMiddleware
    {
        private static readonly string[] HeaderNames = ["x-api-version", "api-version"];

        public async Task InvokeAsync(HttpContext ctx, RequestDelegate next)
        {
            var version =
                HeaderNames.Select(h => ctx.Request.Headers[h].ToString())
                           .FirstOrDefault(v => !string.IsNullOrWhiteSpace(v));

            // default estable
            ctx.Items["api_version"] = string.IsNullOrWhiteSpace(version) ? "1" : version.Trim();

            await next(ctx);
        }
    }

}
