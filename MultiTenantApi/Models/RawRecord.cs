namespace MultiTenantApi.Models;

public sealed class RawRecord
{
    // Internal identifier (never exposed directly)
    public Guid InternalId { get; init; }

    [ApiField("createdAt", Description = "UTC timestamp when the record was created.")]
    public DateTimeOffset CreatedAt { get; init; }

    [ApiField("channel", Description = "Source channel identifier.")]
    public string Channel { get; init; } = "";

    [ApiField("text", Description = "Raw text payload. Consider redaction for PII depending on your domain.")]
    public string Text { get; init; } = "";

    [ApiField("userId", Expose = false, IsIdentifier = true, IsSensitive = true, Masking = "synthetic-id",
        Description = "Internal user identifier. Never exposed in public exports.")]
    public string? UserInternalId { get; init; }
}
