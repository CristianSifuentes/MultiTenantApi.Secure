using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Security.Cryptography;
using System.Text;

namespace MultiTenantApi.Services.HMAC
{

    public interface ICursorProtector
    {
        string Protect(PageCursor cursor);
        bool TryUnprotect(string token, out PageCursor cursor);
    }

    public sealed class HmacCursorProtector : ICursorProtector
    {
        private readonly byte[] _key;
        private static readonly JsonSerializerOptions JsonOpts = new(JsonSerializerDefaults.Web);

        public HmacCursorProtector(IConfiguration cfg)
        {
            // Guardar en KeyVault/Managed Identity en prod.
            var secret = cfg["Pagination:CursorSigningKey"]
                ?? throw new InvalidOperationException("Missing Pagination:CursorSigningKey");
            _key = Encoding.UTF8.GetBytes(secret);
        }

        public string Protect(PageCursor cursor)
        {
            var json = JsonSerializer.Serialize(cursor, JsonOpts);
            var payload = Convert.ToBase64String(Encoding.UTF8.GetBytes(json));

            var sig = ComputeHmac(payload);
            return $"{payload}.{sig}";
        }

        public bool TryUnprotect(string token, out PageCursor cursor)
        {
            cursor = default!;
            var parts = token.Split('.', 2);
            if (parts.Length != 2) return false;

            var payload = parts[0];
            var sig = parts[1];

            if (!FixedTimeEquals(sig, ComputeHmac(payload))) return false;

            byte[] jsonBytes;
            try { jsonBytes = Convert.FromBase64String(payload); }
            catch { return false; }

            try
            {
                cursor = JsonSerializer.Deserialize<PageCursor>(jsonBytes, JsonOpts)!;
                return cursor is not null;
            }
            catch { return false; }
        }

        private string ComputeHmac(string payload)
        {
            using var hmac = new HMACSHA256(_key);
            var bytes = hmac.ComputeHash(Encoding.UTF8.GetBytes(payload));
            return Convert.ToBase64String(bytes);
        }

        private static bool FixedTimeEquals(string a, string b)
        {
            var ba = Convert.TryFromBase64String(a, new Span<byte>(new byte[64]), out var la) ? la : 0;
            var bb = Convert.TryFromBase64String(b, new Span<byte>(new byte[64]), out var lb) ? lb : 0;

            // Fallback simple si no quieres complicarlo: compara bytes directos (no ideal).
            return a.Length == b.Length && CryptographicOperations.FixedTimeEquals(
                Encoding.UTF8.GetBytes(a), Encoding.UTF8.GetBytes(b));
        }
    }

    public static class FilterHasher
    {
            public static string Hash(string? filter)
            {
                filter ??= "";
                using var sha = SHA256.Create();
                var bytes = sha.ComputeHash(Encoding.UTF8.GetBytes(filter));
                return Convert.ToBase64String(bytes);
            }
    }


}
