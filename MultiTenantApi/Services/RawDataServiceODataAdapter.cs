using MultiTenantApi.Models;

namespace MultiTenantApi.Services
{
    public static class RawDataServiceODataAdapter
    {
        public static IQueryable<CallRecordODataDto> AsQueryableForOData(
            this IRawDataService svc,
            string tenantId,
            ISyntheticIdService synth)
        {
            // Demo: if your current implementation is in-memory, you can expose it as IQueryable.
            // Production: return EF Core IQueryable directly.

            if (svc is InMemoryRawDataService mem)
            {
                return mem._data
                    .Where(x => x.TenantId == tenantId)
                    .Select(x => new CallRecordODataDto
                    {
                        Id = synth.Create("raw", x.InternalId.ToString("N")),
                        TenantId = x.TenantId,
                        EndTime = x.EndTime,
                        CallDirection = x.CallDirection,
                        Type = x.Type,
                        Skill = x.Skill
                    })
                    .AsQueryable();
            }

            throw new NotSupportedException("Provide an EF Core IQueryable adapter for production data sources.");
        }
    }

}
