namespace MultiTenantApi.Models
{
    public sealed class CallRecordODataDto
    {
        public string Id { get; set; } = default!;             // Synthetic or external safe id
        public string TenantId { get; set; } = default!;       // optional (can omit from projection)
        public DateTimeOffset EndTime { get; set; }

        public string? CallDirection { get; set; }
        public string? Type { get; set; }
        public string? Skill { get; set; }

        // Example child relation (expand)
        public ICollection<CallSegmentODataDto> Segments { get; set; } = new List<CallSegmentODataDto>();
    }
}
