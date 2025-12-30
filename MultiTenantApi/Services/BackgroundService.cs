using MultiTenantApi.Models;
using MultiTenantApi.Services.JobStore;

namespace MultiTenantApi.Services
{
    public sealed class ExportWorker : BackgroundService
    {
        private readonly IJobQueue _queue;
        private readonly IJobStore _store;
        private readonly IRawDataService _raw;
        private readonly ISyntheticIdService _synth;
        private readonly ILogger<ExportWorker> _log;

        public ExportWorker(
            IJobQueue queue,
            IJobStore store,
            IRawDataService raw,
            ISyntheticIdService synth,
            ILogger<ExportWorker> log)
        {
            _queue = queue;
            _store = store;
            _raw = raw;
            _synth = synth;
            _log = log;
        }

        protected override async Task ExecuteAsync(CancellationToken stoppingToken)
        {
            while (!stoppingToken.IsCancellationRequested)
            {
                var msg = await _queue.DequeueAsync(stoppingToken);

                var ttl = TimeSpan.FromHours(2); // job metadata retention
                var now = DateTimeOffset.UtcNow;

                var running = new JobInfo(
                    JobId: msg.JobId,
                    TenantId: msg.TenantId,
                    Kind: msg.Kind,
                    State: JobState.Running,
                    CreatedUtc: now,
                    StartedUtc: now,
                    CompletedUtc: null,
                    ResultLocation: null,
                    Error: null);

                await _store.SetAsync(running, ttl, stoppingToken);

                try
                {
                    // ✅ Heavylifting fuera del request
                    // Ejemplo: exportar la “primera página” o iterar y generar un archivo
                    var take = Math.Clamp(msg.Payload.Limit ?? 100, 1, 1000);

                    // Asegura ABAC en data layer: tenantId siempre
                    var page = await _raw.QueryAsync(
                        tenantId: msg.TenantId,
                        filter: msg.Payload.Filter,
                        nextToken: msg.Payload.NextPageToken,
                        take: take,
                        ct: stoppingToken);

                    // “Materializa” algo (en real: genera CSV/JSON en blob storage)
                    var shaped = page.Items.Select(r =>
                    {
                        var shape = FieldProjector.ToApiShape(r, _synth);
                        shape["syntheticId"] = _synth.Create("raw", r.InternalId.ToString("N"));
                        return shape;
                    }).ToList();

                    // ✅ Simulación de “result location”
                    // En prod: escribe a Azure Blob / S3 y guarda el URL seguro o un token de descarga
                    var resultLocation = $"inmemory://exports/{msg.JobId}.json";

                    var done = running with
                    {
                        State = JobState.Succeeded,
                        CompletedUtc = DateTimeOffset.UtcNow,
                        ResultLocation = resultLocation
                    };

                    await _store.SetAsync(done, ttl, stoppingToken);

                    _log.LogInformation("Job {JobId} succeeded for tenant {TenantId}", msg.JobId, msg.TenantId);
                }
                catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
                {
                    var canceled = (await _store.GetAsync(msg.JobId, stoppingToken))!;
                    await _store.SetAsync(canceled with { State = JobState.Canceled, CompletedUtc = DateTimeOffset.UtcNow }, TimeSpan.FromHours(2), stoppingToken);
                }
                catch (Exception ex)
                {
                    var failed = (await _store.GetAsync(msg.JobId, stoppingToken))!;
                    await _store.SetAsync(failed with { State = JobState.Failed, CompletedUtc = DateTimeOffset.UtcNow, Error = ex.Message }, TimeSpan.FromHours(2), stoppingToken);

                    _log.LogError(ex, "Job {JobId} failed", msg.JobId);
                }
            }
        }
    }
 
}
