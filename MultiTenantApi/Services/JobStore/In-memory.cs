using System.Security.Claims;
using System.Threading.Channels;

namespace MultiTenantApi.Services.JobStore
{


    public sealed record JobMessage(
        string JobId,
        string TenantId,
        string Kind,
        StartExportRequest Payload,
        ClaimsPrincipal Principal // o extrae claims necesarios y guarda “snapshot”
    );

    public interface IJobQueue
    {
        ValueTask EnqueueAsync(JobMessage msg, CancellationToken ct);
        ValueTask<JobMessage> DequeueAsync(CancellationToken ct);
    }

    public sealed class InMemoryJobQueue : IJobQueue
    {
        private readonly Channel<JobMessage> _ch = Channel.CreateBounded<JobMessage>(
            new BoundedChannelOptions(capacity: 1000)
            {
                FullMode = BoundedChannelFullMode.Wait,
                SingleReader = true,
                SingleWriter = false
            });

        public ValueTask EnqueueAsync(JobMessage msg, CancellationToken ct)
            => _ch.Writer.WriteAsync(msg, ct);

        public ValueTask<JobMessage> DequeueAsync(CancellationToken ct)
            => _ch.Reader.ReadAsync(ct);
    }

}
