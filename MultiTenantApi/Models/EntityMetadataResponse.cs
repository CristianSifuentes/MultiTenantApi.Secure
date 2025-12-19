namespace MultiTenantApi.Models;

public sealed record EntityMetadataResponse<T>(
    string EntityName,
    string Version,
    IReadOnlyList<ApiFieldMetadata> Fields,
    IReadOnlyList<T> Sample
);
