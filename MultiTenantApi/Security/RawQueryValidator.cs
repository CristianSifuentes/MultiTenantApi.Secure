using System.Text.RegularExpressions;

namespace MultiTenantApi.Security;

public static class RawQueryValidator
{
    // Ajusta según necesidades reales
    public const int MaxFilterLength = 128;     // evita DoS por strings gigantes
    public const int MaxNextTokenLength = 16;   // "1234567890" etc.
    public const int MaxTake = 100;

    // Deny-by-default: permite letras, números, espacios y algunos símbolos comunes.
    // Si necesitas más, extiende conscientemente.
    private static readonly Regex FilterAllowed =
        new(@"^[a-zA-Z0-9\s\-\._:/@]+$", RegexOptions.Compiled);

    public static (bool ok, string? error, int? offset) Validate(string? filter, string? nextToken, int take)
    {
        // Range
        if (take < 1 || take > MaxTake)
            return (false, $"take must be between 1 and {MaxTake}.", null);

        // Size
        if (!string.IsNullOrEmpty(filter) && filter.Length > MaxFilterLength)
            return (false, $"filter too long. Max {MaxFilterLength} characters.", null);

        if (!string.IsNullOrEmpty(nextToken) && nextToken.Length > MaxNextTokenLength)
            return (false, $"nextToken too long. Max {MaxNextTokenLength} characters.", null);

        // Format (deny-by-default)
        if (!string.IsNullOrWhiteSpace(filter))
        {
            var f = Normalize(filter);

            // Si tu negocio permite “cualquier string”, entonces no uses regex.
            // Pero si es API pública, deny-by-default es más seguro.
            if (!FilterAllowed.IsMatch(f))
                return (false, "filter contains unsupported characters.", null);
        }

        // Format: nextToken must be digits only
        int offset = 0;
        if (!string.IsNullOrWhiteSpace(nextToken))
        {
            // Solo dígitos (evita "1;DROP", "1 2", etc.)
            foreach (var ch in nextToken)
                if (ch < '0' || ch > '9')
                    return (false, "nextToken must be a numeric cursor.", null);

            if (!int.TryParse(nextToken, out offset) || offset < 0)
                return (false, "nextToken is invalid.", null);
        }

        return (true, null, offset);
    }

    public static string Normalize(string value)
        => string.Join(' ', value.Trim().Split(' ', StringSplitOptions.RemoveEmptyEntries));
}
