namespace MultiTenantApi.Models;

/// <summary>
/// Internal IVR/AutoAttendant context. This is intentionally NOT exposed in export DTOs.
/// </summary>
public sealed class InMenu
{
    public int AutoAttendantId { get; init; }
    public int InteractionStatusId { get; init; }
    public double Duration { get; init; }
    public int InteractionId { get; init; }
    public string Skill { get; init; } = "";
    public DateTimeOffset StartDate { get; init; }
    public DateTimeOffset EndDate { get; init; }
    public int Id { get; init; }
    public Guid Oid { get; init; }
    public int ClientId { get; init; }
}
