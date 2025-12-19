namespace MultiTenantApi.Models;

public sealed record CallRecordExportDto
{
    public string SyntheticCallId { get; init; } = "";

    public string CallDirection { get; init; } = "";
    public string Type { get; init; } = "";

    public bool Accepted { get; init; }
    public bool Missed { get; init; }
    public bool Abandoned { get; init; }

    public DateTimeOffset EndTime { get; init; }

    public double QueueTime { get; init; }
    public double TalkTime { get; init; }
    public double CallTime { get; init; }

    public string Skill { get; init; } = "";

    public string? AnsweredByAlias { get; init; }
    public string? NotHandledByAlias { get; init; }
    public string? CallerNumberMasked { get; init; }
}
