namespace MultiTenantApi.Models;

public sealed class CallRecord
{
    // Internal identifiers
    public string CallId { get; init; } = Guid.NewGuid().ToString();
    public int InteractionId { get; init; }

    [ApiField("callDirection")]
    public string CallDirection { get; init; } = "Inbound";

    [ApiField("type")]
    public string Type { get; init; } = "Missed";

    [ApiField("accepted")]
    public bool Accepted { get; init; }

    [ApiField("missed")]
    public bool Missed { get; init; }

    [ApiField("endTime")]
    public DateTimeOffset EndTime { get; init; }

    [ApiField("queueTime")]
    public double QueueTime { get; init; }

    [ApiField("talkTime")]
    public double TalkTime { get; init; }

    [ApiField("callTime")]
    public double CallTime { get; init; }

    [ApiField("skill")]
    public string Skill { get; init; } = "";

    [ApiField("answeredBy", IsSensitive = true, Masking = "agent-alias")]
    public string? AnsweredBy { get; init; }

    [ApiField("notHandledBy", IsSensitive = true, Masking = "agent-alias")]
    public string? NotHandledBy { get; init; }

    [ApiField("callerNumber", IsSensitive = true, Masking = "phone")]
    public string? CallerNumber { get; init; }

    // Internal nested info (not exposed)
    [ApiField("inMenu", Expose = false)]
    public InMenu? InMenu { get; init; }
}
