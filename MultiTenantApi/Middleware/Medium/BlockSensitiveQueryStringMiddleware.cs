namespace MultiTenantApi.Middleware.Medium
{
    public sealed class BlockSensitiveQueryStringMiddleware : IMiddleware
    {
        private static readonly HashSet<string> Blocked = new(StringComparer.OrdinalIgnoreCase)
    {
        "access_token", "token", "id_token", "refresh_token", "client_secret", "secret", "jti", "apikey", "api_key"
    };

        public Task InvokeAsync(HttpContext ctx, RequestDelegate next)
        {
            foreach (var key in ctx.Request.Query.Keys)
            {
                if (Blocked.Contains(key))
                {
                    ctx.Response.StatusCode = StatusCodes.Status400BadRequest;
                    return ctx.Response.WriteAsJsonAsync(new
                    {
                        error = "forbidden_query_param",
                        message = $"Query parameter '{key}' is not allowed. Use headers or request body."
                    });
                }
            }

            return next(ctx);
        }
    }

}
