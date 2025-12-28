using MultiTenantApi.Security.ProblemDetails;

namespace MultiTenantApi.Middleware
{
    public sealed class AuthProblemDetailsMiddleware : IMiddleware
    {
        public async Task InvokeAsync(HttpContext ctx, RequestDelegate next)
        {
            await next(ctx);

            if (ctx.Response.HasStarted) return;

            if (ctx.Response.StatusCode == StatusCodes.Status401Unauthorized)
            {
                await Problem.Create(ctx, 401, ApiErrorCodes.Unauthorized,
                    "Unauthorized.", "A valid bearer token is required.")
                    .ExecuteAsync(ctx);
            }
            else if (ctx.Response.StatusCode == StatusCodes.Status403Forbidden)
            {
                await Problem.Create(ctx, 403, ApiErrorCodes.Forbidden,
                    "Forbidden.", "You don't have permission to access this resource.")
                    .ExecuteAsync(ctx);
            }
        }
    }

}
