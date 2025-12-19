namespace MultiTenantApi.Services;

public sealed record PageResult<T>(IReadOnlyList<T> Items, string? NextToken);
