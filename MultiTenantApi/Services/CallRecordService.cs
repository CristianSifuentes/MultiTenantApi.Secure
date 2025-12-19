using MultiTenantApi.Models;

namespace MultiTenantApi.Services;

public interface ICallRecordService
{
    Task<List<CallRecord>> GetSampleAsync(CancellationToken ct);
}

public sealed class InMemoryCallRecordService : ICallRecordService
{
    private readonly List<CallRecord> _base;

    public InMemoryCallRecordService()
    {
        _base = new List<CallRecord>
        {
            new()
            {
                CallId = Guid.NewGuid().ToString(),
                InteractionId = 2508,
                CallDirection = "Inbound",
                Type = "Missed",
                Accepted = false,
                Missed = true,
                EndTime = DateTimeOffset.UtcNow.AddMinutes(-10),
                QueueTime = 19.03,
                TalkTime = 0,
                CallTime = 19.03,
                Skill = "",
                AnsweredBy = "Jane Doe",
                NotHandledBy = "John Smith",
                CallerNumber = "+52 55 1234 5678",
                InMenu = new InMenu
                {
                    AutoAttendantId = 1,
                    InteractionStatusId = 2,
                    Duration = 19.03,
                    InteractionId = 2508,
                    Skill = "",
                    StartDate = DateTimeOffset.UtcNow.AddMinutes(-10),
                    EndDate = DateTimeOffset.UtcNow.AddMinutes(-10).AddSeconds(19),
                    Id = 76329,
                    Oid = Guid.NewGuid(),
                    ClientId = 1
                }
            },
            new()
            {
                CallId = Guid.NewGuid().ToString(),
                InteractionId = 2509,
                CallDirection = "Inbound",
                Type = "Abandoned",
                Accepted = false,
                Missed = false,
                EndTime = DateTimeOffset.UtcNow.AddMinutes(-8),
                QueueTime = 30,
                TalkTime = 0,
                CallTime = 30,
                Skill = "Spanish",
                AnsweredBy = null,
                NotHandledBy = "Queue",
                CallerNumber = "+52 81 9876 5432",
                InMenu = null
            }
        };
    }

    public Task<List<CallRecord>> GetSampleAsync(CancellationToken ct)
    {
        // Return a larger sample set for demo
        var list = new List<CallRecord>(_base.Count * 50);
        for (var i = 0; i < 50; i++)
        {
            foreach (var r in _base)
            {
                list.Add(new CallRecord
                {
                    CallId = Guid.NewGuid().ToString(),
                    InteractionId = r.InteractionId + i,
                    CallDirection = r.CallDirection,
                    Type = r.Type,
                    Accepted = r.Accepted,
                    Missed = r.Missed,
                    EndTime = r.EndTime.AddSeconds(-i),
                    QueueTime = r.QueueTime,
                    TalkTime = r.TalkTime,
                    CallTime = r.CallTime,
                    Skill = r.Skill,
                    AnsweredBy = r.AnsweredBy,
                    NotHandledBy = r.NotHandledBy,
                    CallerNumber = r.CallerNumber,
                    InMenu = r.InMenu
                });
            }
        }

        return Task.FromResult(list);
    }
}
