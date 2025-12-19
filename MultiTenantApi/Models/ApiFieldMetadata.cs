namespace MultiTenantApi.Models;

public sealed record ApiFieldMetadata(
    string JsonName,
    string DotNetName,
    string DotNetType,
    bool IsSensitive,
    bool IsIdentifier,
    string? Masking,
    string? Description
);
