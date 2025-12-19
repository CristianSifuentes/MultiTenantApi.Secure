using System.Buffers;
using System.Security.Cryptography;
using System.Text;

using Microsoft.Extensions.Options;

using MultiTenantApi.Common;

namespace MultiTenantApi.Models;

/// <summary>
/// Deterministic, non-reversible pseudonymous identifier generator.
/// Uses HMAC-SHA256 with a secret key (NOT a public salt).
///
/// Security notes:
/// - Deterministic: same input -> same output (useful for exports, joins, correlation).
/// - Non-reversible without the key.
/// - Key must be managed as a secret (KeyVault, env var, secret manager).
/// - Include an environment namespace to prevent cross-environment correlation.
/// </summary>
public interface ISyntheticIdService
{
    string Create(params string[] parts);
}

public sealed class SyntheticIdService : ISyntheticIdService
{
    private readonly byte[] _key;
    private readonly string _ns;

    public SyntheticIdService(IOptions<SyntheticIdOptions> options)
    {
        var opt = options.Value;

        if (string.IsNullOrWhiteSpace(opt.KeyBase64))
            throw new InvalidOperationException("SyntheticId:KeyBase64 is required.");

        _key = Convert.FromBase64String(opt.KeyBase64);
        if (_key.Length != 32)
            throw new InvalidOperationException("SyntheticId:KeyBase64 must decode to exactly 32 bytes (HMAC-SHA256 key).");

        _ns = string.IsNullOrWhiteSpace(opt.Namespace) ? "default" : opt.Namespace.Trim();
    }

    public string Create(params string[] parts)
    {
        // Canonicalize inputs (trim + invariant lower) to reduce accidental mismatches.
        // If your identifiers are case-sensitive, remove ToLowerInvariant().
        var normalized = parts.Select(p => (p ?? string.Empty).Trim()).ToArray();

        // Safer than string.Join("|", ...) because it is unambiguous:
        // length-prefix encoding: [len][bytes]...
        using var hmac = new HMACSHA256(_key);

        var buffer = ArrayPool<byte>.Shared.Rent(4096);
        try
        {
            int offset = 0;

            void WriteInt(int value)
            {
                // little-endian 4 bytes
                buffer[offset++] = (byte)value;
                buffer[offset++] = (byte)(value >> 8);
                buffer[offset++] = (byte)(value >> 16);
                buffer[offset++] = (byte)(value >> 24);
            }

            void WriteBytes(byte[] bytes)
            {
                if (offset + bytes.Length > buffer.Length)
                    throw new InvalidOperationException("SyntheticId payload too large. Consider hashing individual parts first.");

                bytes.CopyTo(buffer, offset);
                offset += bytes.Length;
            }

            // Prefix environment namespace
            var nsBytes = Encoding.UTF8.GetBytes(_ns);
            WriteInt(nsBytes.Length);
            WriteBytes(nsBytes);

            foreach (var s in normalized)
            {
                var bytes = Encoding.UTF8.GetBytes(s);
                WriteInt(bytes.Length);
                WriteBytes(bytes);
            }

            var hash = hmac.ComputeHash(buffer, 0, offset);
            return Convert.ToHexString(hash);
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(buffer);
        }
    }
}
