using MultiTenantApi.Security.IdempotencyStore;

namespace MultiTenantApi.Middleware
{
    public sealed class IdempotencyMiddleware : IMiddleware
    {
        private readonly IIdempotencyStore _store;

        public IdempotencyMiddleware(IIdempotencyStore store) => _store = store;

        public async Task InvokeAsync(HttpContext ctx, RequestDelegate next)
        {
            // Only for "unsafe" methods
            if (!(HttpMethods.IsPost(ctx.Request.Method) ||
                  HttpMethods.IsPut(ctx.Request.Method) ||
                  HttpMethods.IsPatch(ctx.Request.Method)))
            {
                await next(ctx);
                return;
            }

            // Apply only to a subset (payments/orders/onboarding), not everything
            if (!ctx.Request.Path.StartsWithSegments("/api/v1/payments") &&
                !ctx.Request.Path.StartsWithSegments("/api/v1/orders") &&
                !ctx.Request.Path.StartsWithSegments("/api/v1/onboarding"))
            {
                await next(ctx);
                return;
            }

            var key = ctx.Request.Headers["Idempotency-Key"].ToString();
            if (string.IsNullOrWhiteSpace(key) || key.Length > 128)
            {
                ctx.Response.StatusCode = StatusCodes.Status400BadRequest;
                await ctx.Response.WriteAsJsonAsync(new
                {
                    error = "missing_idempotency_key",
                    message = "Idempotency-Key header is required for this operation."
                });
                return;
            }

            // If completed: replay response
            var existing = await _store.GetAsync(key, ctx.RequestAborted);
            if (existing is { Completed: true, Response: not null })
            {
                ctx.Response.StatusCode = existing.Response.StatusCode;
                ctx.Response.ContentType = existing.Response.ContentType;
                await ctx.Response.Body.WriteAsync(existing.Response.Body, ctx.RequestAborted);
                return;
            }

            // Try start (lock)
            var started = await _store.TryStartAsync(key, ttl: TimeSpan.FromHours(24), ctx.RequestAborted);
            if (!started)
            {
                // request in-flight or already reserved
                ctx.Response.StatusCode = StatusCodes.Status409Conflict;
                await ctx.Response.WriteAsJsonAsync(new
                {
                    error = "idempotency_conflict",
                    message = "A request with the same Idempotency-Key is already being processed."
                });
                return;
            }

            // Capture response
            var originalBody = ctx.Response.Body;
            await using var ms = new MemoryStream();
            ctx.Response.Body = ms;

            await next(ctx);

            // Save only “success-like” responses
            ms.Position = 0;
            var bodyBytes = ms.ToArray();

            if (ctx.Response.StatusCode is >= 200 and < 300)
            {
                await _store.CompleteAsync(
                    key,
                    new IdempotencyResponse(ctx.Response.StatusCode, ctx.Response.ContentType ?? "application/json", bodyBytes),
                    ttl: TimeSpan.FromHours(24),
                    ctx.RequestAborted);
            }

            ms.Position = 0;
            await ms.CopyToAsync(originalBody, ctx.RequestAborted);
            ctx.Response.Body = originalBody;
        }
    }

}
