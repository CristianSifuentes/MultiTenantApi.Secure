namespace MultiTenantApi.Models;

[AttributeUsage(AttributeTargets.Property, AllowMultiple = false)]
public sealed class ApiFieldAttribute : Attribute
{
    public ApiFieldAttribute(string jsonName)
    {
        JsonName = jsonName;
    }

    public string JsonName { get; }

    public bool Expose { get; init; } = true;

    public bool IsSensitive { get; init; } = false;

    public bool IsIdentifier { get; init; } = false;

    /// <summary>
    /// Optional masking strategy name, e.g. "phone", "agent-alias", "synthetic-id"
    /// </summary>
    public string? Masking { get; init; }

    public string? Description { get; init; }
}
