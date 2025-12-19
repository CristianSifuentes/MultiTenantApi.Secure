using System.Collections.Concurrent;
using System.Reflection;

using MultiTenantApi.Infrastructure;

namespace MultiTenantApi.Models;

/// <summary>
/// Projects an entity into an API-safe dictionary:
/// - Whitelist-only exposure via [ApiField(Expose=true)]
/// - Optional masking per field (phone, agent alias, synthetic-id, etc.)
/// - Cached reflection metadata for performance
/// </summary>
public static class FieldProjector
{
    private sealed record FieldAccessor(string JsonName, PropertyInfo Property, ApiFieldAttribute Meta);

    private static readonly ConcurrentDictionary<Type, IReadOnlyList<FieldAccessor>> Cache = new();

    public static IDictionary<string, object?> ToApiShape<T>(T entity, ISyntheticIdService synth)
    {
        if (entity is null) return new Dictionary<string, object?>();

        var accessors = Cache.GetOrAdd(typeof(T), static t =>
        {
            var list = new List<FieldAccessor>();
            foreach (var p in t.GetProperties(BindingFlags.Instance | BindingFlags.Public))
            {
                var meta = p.GetCustomAttribute<ApiFieldAttribute>();
                if (meta?.Expose == true)
                    list.Add(new FieldAccessor(meta.JsonName, p, meta));
            }
            return list;
        });

        var dict = new Dictionary<string, object?>(capacity: accessors.Count, StringComparer.Ordinal);

        foreach (var a in accessors)
        {
            var raw = a.Property.GetValue(entity);

            // Apply masking only when configured.
            if (!string.IsNullOrWhiteSpace(a.Meta.Masking))
            {
                dict[a.JsonName] = ApplyMasking(a.Meta.Masking!, raw, synth);
            }
            else
            {
                dict[a.JsonName] = raw;
            }
        }

        return dict;
    }

    private static object? ApplyMasking(string strategy, object? value, ISyntheticIdService synth)
    {
        if (value is null) return null;

        switch (strategy.Trim().ToLowerInvariant())
        {
            case "phone":
                return Masking.MaskPhone(value.ToString());

            case "agent-alias":
                return Masking.MaskAgentName(value.ToString());

            case "synthetic-id":
                return synth.Create("field", value.ToString() ?? string.Empty);

            default:
                // Unknown strategy: fail closed-ish (do not leak raw for sensitive fields).
                // You can choose to return null or raw depending on your risk tolerance.
                return null;
        }
    }
}
