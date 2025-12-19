using Mapster;

using MultiTenantApi.Infrastructure;
using MultiTenantApi.Models;

namespace MultiTenantApi.Mapping;

public static class MapsterConfig
{
    public static void RegisterMaps()
    {
        TypeAdapterConfig<CallRecord, CallRecordExportDto>
            .NewConfig()
            // Synthetic id is filled by endpoint/service (needs secret key)
            .Ignore(dest => dest.SyntheticCallId)
            .Map(dest => dest.CallDirection, src => src.CallDirection)
            .Map(dest => dest.Type, src => src.Type)
            .Map(dest => dest.Accepted, src => src.Accepted)
            .Map(dest => dest.Missed, src => src.Missed)
            .Map(dest => dest.Abandoned, src => src.Type == "Abandoned")
            .Map(dest => dest.EndTime, src => src.EndTime)
            .Map(dest => dest.QueueTime, src => src.QueueTime)
            .Map(dest => dest.TalkTime, src => src.TalkTime)
            .Map(dest => dest.CallTime, src => src.CallTime)
            .Map(dest => dest.Skill, src => src.Skill)
            .Map(dest => dest.AnsweredByAlias, src => Masking.MaskAgentName(src.AnsweredBy))
            .Map(dest => dest.NotHandledByAlias, src => Masking.MaskAgentName(src.NotHandledBy))
            .Map(dest => dest.CallerNumberMasked, src => Masking.MaskPhone(src.CallerNumber))
            .IgnoreNonMapped(true);
    }
}
