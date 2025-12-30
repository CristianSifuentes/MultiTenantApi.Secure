using Microsoft.AspNetCore.Http;

namespace MultiTenantApi.Middleware.Medium;

public sealed class DenySecretsInUrlMiddleware : IMiddleware
{
    private static readonly string[] DangerousKeys =
    {
        "access_token", "token", "id_token", "refresh_token",
        "client_secret", "secret", "apikey", "api_key", "code"
    };

    public async Task InvokeAsync(HttpContext ctx, RequestDelegate next)
    {
        if (ctx.Request.Query.Count > 0)
        {
            foreach (var key in DangerousKeys)
            {
                if (ctx.Request.Query.ContainsKey(key))
                {
                    ctx.Response.StatusCode = StatusCodes.Status400BadRequest;
                    await ctx.Response.WriteAsJsonAsync(new
                    {
                        error = "secrets_in_url_not_allowed",
                        message = $"Query parameter '{key}' is not allowed."
                    });
                    return;
                }
            }
        }

        await next(ctx);
    }
}
