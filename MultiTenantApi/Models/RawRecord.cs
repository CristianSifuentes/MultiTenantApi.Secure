namespace MultiTenantApi.Models;

//public sealed class RawRecord
//{
//    // Internal identifier (never exposed directly)
//    public Guid InternalId { get; init; }

//    [ApiField("createdAt", Description = "UTC timestamp when the record was created.")]
//    public DateTimeOffset CreatedAt { get; init; }

//    [ApiField("channel", Description = "Source channel identifier.")]
//    public string Channel { get; init; } = "";

//    [ApiField("text", Description = "Raw text payload. Consider redaction for PII depending on your domain.")]
//    public string Text { get; init; } = "";

//    [ApiField("userId", Expose = false, IsIdentifier = true, IsSensitive = true, Masking = "synthetic-id",
//        Description = "Internal user identifier. Never exposed in public exports.")]
//    public string? UserInternalId { get; init; }

//    // ✅ ABAC attribute: tenant scoping
//    public string TenantId { get; set; } = default!;
//}
using System.Security.Cryptography;
using System.Text;
using MultiTenantApi.Models;

public sealed class RawRecord
{
    // Internal identifier (never exposed directly)
    public Guid InternalId { get; init; }

    // ✅ ABAC attribute: tenant scoping (NO lo quites)
    public string TenantId { get; set; } = default!;

    // =========================
    // Public API fields (Call)
    // =========================

    [ApiField("syntheticCallId", Description = "Stable synthetic identifier safe to expose publicly.")]
    public string SyntheticCallId { get; init; } = "";

    [ApiField("callDirection", Description = "Inbound/Outbound")]
    public string CallDirection { get; init; } = "Inbound";

    [ApiField("type", Description = "Missed/Abandoned/Answered")]
    public string Type { get; init; } = "Missed";

    [ApiField("accepted")]
    public bool Accepted { get; init; }

    [ApiField("missed")]
    public bool Missed { get; init; }

    [ApiField("abandoned")]
    public bool Abandoned { get; init; }

    [ApiField("endTime", Description = "UTC timestamp when the call ended.")]
    public DateTimeOffset EndTime { get; init; }

    [ApiField("queueTime", Description = "Seconds spent waiting in queue.")]
    public double QueueTime { get; init; }

    [ApiField("talkTime", Description = "Seconds in talk time (0 if not answered).")]
    public double TalkTime { get; init; }

    [ApiField("callTime", Description = "Total call time in seconds (queue + talk).")]
    public double CallTime { get; init; }

    [ApiField("skill", Description = "Routing skill/language.")]
    public string Skill { get; init; } = "";

    [ApiField("answeredByAlias", Description = "Masked agent alias that answered (null if not answered).")]
    public string? AnsweredByAlias { get; init; }

    [ApiField("notHandledByAlias", Description = "Masked agent alias that did not handle (e.g., abandoned/missed).")]
    public string? NotHandledByAlias { get; init; }

    [ApiField("callerNumberMasked", Description = "Masked caller phone number.")]
    public string CallerNumberMasked { get; init; } = "********0000";

    // =========================
    // Optional: keep old fields hidden or remove if ya no aplican
    // =========================

    [ApiField("createdAt", Expose = false)]
    public DateTimeOffset CreatedAt { get; init; } // puedes dejarlo interno

    [ApiField("channel", Expose = false)]
    public string Channel { get; init; } = "";

    [ApiField("text", Expose = false)]
    public string Text { get; init; } = "";

    [ApiField("userId", Expose = false, IsIdentifier = true, IsSensitive = true, Masking = "synthetic-id")]
    public string? UserInternalId { get; init; }

    // Helper (si lo quieres dentro del modelo)
    public static string MakeSyntheticCallId(Guid internalId, string tenantId, DateTimeOffset endTimeUtc)
    {
        var input = $"{tenantId}|{internalId:N}|{endTimeUtc.UtcTicks}";
        var bytes = SHA256.HashData(Encoding.UTF8.GetBytes(input));
        return Convert.ToHexString(bytes); // 64 hex chars
    }
}
