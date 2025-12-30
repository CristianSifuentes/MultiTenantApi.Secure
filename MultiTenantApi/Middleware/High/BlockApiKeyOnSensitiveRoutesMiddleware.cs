namespace MultiTenantApi.Middleware.High
{
    public sealed class BlockApiKeyOnSensitiveRoutesMiddleware : IMiddleware
    {
        public async Task InvokeAsync(HttpContext ctx, RequestDelegate next)
        {
            var path = ctx.Request.Path.Value ?? "";

            var isSensitive =
                path.StartsWith("/export", StringComparison.OrdinalIgnoreCase) ||
                path.StartsWith("/raw-data", StringComparison.OrdinalIgnoreCase);

            if (isSensitive && ctx.Request.Headers.ContainsKey("x-api-key"))
            {
                ctx.Response.StatusCode = StatusCodes.Status403Forbidden;
                await ctx.Response.WriteAsJsonAsync(new { error = "api_key_not_allowed_for_sensitive_endpoints" });
                return;
            }

            await next(ctx);
        }
    }
}
