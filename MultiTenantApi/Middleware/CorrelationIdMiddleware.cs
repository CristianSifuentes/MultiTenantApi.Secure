using Serilog.Context;

namespace MultiTenantApi.Middleware;


//public sealed class CorrelationIdMiddleware : IMiddleware
//{
//    public const string HeaderName = "X-Correlation-ID";

//    public async Task InvokeAsync(HttpContext ctx, RequestDelegate next)
//    {
//        var corr =
//            ctx.Request.Headers.TryGetValue(HeaderName, out var v) && !string.IsNullOrWhiteSpace(v)
//                ? v.ToString()
//                : Guid.NewGuid().ToString("N");

//        ctx.TraceIdentifier = corr;
//        ctx.Response.Headers[HeaderName] = corr;

//        using (LogContext.PushProperty("correlation_id", corr))
//        using (LogContext.PushProperty("request_id", ctx.TraceIdentifier))
//        {
//            await next(ctx);
//        }
//    }
//}
public sealed class CorrelationIdMiddleware(RequestDelegate next)
{
    public const string HeaderName = "X-Correlation-ID";

    public async Task InvokeAsync(HttpContext context)
    {
        var correlationId = context.Request.Headers.TryGetValue(HeaderName, out var v) && !string.IsNullOrWhiteSpace(v)
            ? v.ToString()
            : Guid.NewGuid().ToString("N");

        context.Items[HeaderName] = correlationId;
        context.Response.Headers[HeaderName] = correlationId;

        using (LogContext.PushProperty("CorrelationId", correlationId))
        {
            await next(context);
        }
    }
}
