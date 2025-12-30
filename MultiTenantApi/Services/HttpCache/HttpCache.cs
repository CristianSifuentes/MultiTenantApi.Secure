using System.Security.Cryptography;
using System.Text;


namespace MultiTenantApi.Services.HttpCache
{

    public static class HttpCache
    {
        public static string ComputeWeakETag(string input)
        {
            // Weak ETag: W/"...."  (permite semántica de equivalencia, no byte-perfect)
            using var sha = SHA256.Create();
            var hash = sha.ComputeHash(Encoding.UTF8.GetBytes(input));
            return $"W/\"{Convert.ToHexString(hash)}\"";
        }

        public static IResult ETagOrOk(HttpContext http, string etag, object body, int maxAgeSeconds = 30)
        {
            http.Response.Headers.ETag = etag;

            // Importante: Vary por Authorization para evitar mezclar usuarios/tenants en caches intermedios
            http.Response.Headers.Vary = "Authorization";

            // Client cache: private (por usuario), short TTL
            http.Response.Headers.CacheControl = $"private, max-age={maxAgeSeconds}, must-revalidate";

            var inm = http.Request.Headers.IfNoneMatch.ToString();
            if (!string.IsNullOrWhiteSpace(inm) && string.Equals(inm, etag, StringComparison.Ordinal))
                return Results.StatusCode(StatusCodes.Status304NotModified);

            return Results.Ok(body);
        }
    }

}
