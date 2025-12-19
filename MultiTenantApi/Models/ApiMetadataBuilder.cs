using System.Collections.Concurrent;
using System.Reflection;

namespace MultiTenantApi.Models;

public static class ApiMetadataBuilder
{
    private static readonly ConcurrentDictionary<Type, IReadOnlyList<ApiFieldMetadata>> Cache = new();

    public static IReadOnlyList<ApiFieldMetadata> BuildFor<T>() => BuildFor(typeof(T));

    public static IReadOnlyList<ApiFieldMetadata> BuildFor(Type t)
    {
        return Cache.GetOrAdd(t, static type =>
        {
            var fields = new List<ApiFieldMetadata>();

            foreach (var p in type.GetProperties(BindingFlags.Instance | BindingFlags.Public))
            {
                var a = p.GetCustomAttribute<ApiFieldAttribute>();
                if (a?.Expose == true)
                {
                    fields.Add(new ApiFieldMetadata(
                        JsonName: a.JsonName,
                        DotNetName: p.Name,
                        DotNetType: p.PropertyType.FullName ?? p.PropertyType.Name,
                        IsSensitive: a.IsSensitive,
                        IsIdentifier: a.IsIdentifier,
                        Masking: a.Masking,
                        Description: a.Description
                    ));
                }
            }

            return fields;
        });
    }
}
