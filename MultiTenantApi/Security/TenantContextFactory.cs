using System.Security;
using System.Security.Claims;

public sealed record TenantContext(string TenantId, string? ObjectId, string? ClientAppId);


namespace MultiTenantApi.Security
{
    public static class TenantContextFactory
    {
        public static TenantContext From(ClaimsPrincipal user)
            => new(
                TenantId: user.FindFirstValue("tid") ?? throw new SecurityException("Missing tid"),
                ObjectId: user.FindFirstValue("oid"),
                ClientAppId: user.FindFirstValue("azp") ?? user.FindFirstValue("appid"));
    }
}
