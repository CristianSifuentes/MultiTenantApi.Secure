using System.Text.RegularExpressions;

namespace MultiTenantApi.Infrastructure;

public static partial class Masking
{
    public static string? MaskPhone(string? phone)
    {
        if (string.IsNullOrWhiteSpace(phone)) return phone;

        // Keep last 4 digits; remove non-digits
        var digits = Regex.Replace(phone, @"\D", "");
        if (digits.Length <= 4) return "****";

        return new string('*', Math.Max(0, digits.Length - 4)) + digits[^4..];
    }

    public static string? MaskAgentName(string? name)
    {
        if (string.IsNullOrWhiteSpace(name)) return name;

        // "Jane Doe" -> "J*** D**"
        var parts = name.Trim().Split(' ', StringSplitOptions.RemoveEmptyEntries);
        var masked = parts.Select(p =>
        {
            if (p.Length <= 1) return "*";
            if (p.Length == 2) return p[0] + "*";
            return p[0] + new string('*', p.Length - 1);
        });

        return string.Join(' ', masked);
    }
}
