using System.IdentityModel.Tokens.Jwt;
using Microsoft.Extensions.Options;
using MultiTenantApi.Security;

namespace MultiTenantApi.Middleware;

public sealed class TokenAgeGuardMiddleware : IMiddleware
{
    private readonly IOptions<TokenHardeningOptions> _opt;

    public TokenAgeGuardMiddleware(IOptions<TokenHardeningOptions> opt) => _opt = opt;

    public async Task InvokeAsync(HttpContext ctx, RequestDelegate next)
    {
        // Only enforce when authenticated (avoid breaking /health)
        if (ctx.User?.Identity?.IsAuthenticated != true)
        {
            await next(ctx);
            return;
        }

        // Read raw bearer token (more reliable than relying on claim presence)
        var auth = ctx.Request.Headers.Authorization.ToString();
        if (string.IsNullOrWhiteSpace(auth) || !auth.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase))
        {
            await next(ctx);
            return;
        }

        var tokenString = auth["Bearer ".Length..].Trim();
        JwtSecurityToken jwt;
        try
        {
            jwt = new JwtSecurityTokenHandler().ReadJwtToken(tokenString);
        }
        catch
        {
            ctx.Response.StatusCode = StatusCodes.Status401Unauthorized;
            await ctx.Response.WriteAsJsonAsync(new { error = "invalid_token" });
            return;
        }

        var o = _opt.Value;
        var maxAge = TimeSpan.FromMinutes(Math.Clamp(o.MaxAccessTokenAgeMinutes, 1, 60));

        // iat is optional, but for strict mode we enforce it
        // Entra typically includes iat in access tokens.
        var iatClaim = jwt.Claims.FirstOrDefault(c => c.Type == JwtRegisteredClaimNames.Iat)?.Value;
        if (iatClaim is null || !long.TryParse(iatClaim, out var iatSeconds))
        {
            ctx.Response.StatusCode = StatusCodes.Status401Unauthorized;
            await ctx.Response.WriteAsJsonAsync(new { error = "missing_iat" });
            return;
        }

        var issuedAt = DateTimeOffset.FromUnixTimeSeconds(iatSeconds);
        var now = DateTimeOffset.UtcNow;

        // If too old -> reject
        if (now - issuedAt > maxAge + TimeSpan.FromSeconds(o.ClockSkewSeconds))
        {
            ctx.Response.StatusCode = StatusCodes.Status401Unauthorized;
            await ctx.Response.WriteAsJsonAsync(new { error = "token_too_old", maxAgeMinutes = o.MaxAccessTokenAgeMinutes });
            return;
        }

        await next(ctx);
    }
}
