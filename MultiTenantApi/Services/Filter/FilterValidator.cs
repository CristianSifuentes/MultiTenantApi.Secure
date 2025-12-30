using MultiTenantApi.Common;
using MultiTenantApi.Models;

namespace MultiTenantApi.Services.Filter
{
    public static class FilterValidator
    {
        static readonly HashSet<string> AllowedFields = new(StringComparer.OrdinalIgnoreCase)
            {
                "type",
                "callDirection",
                "skill",
                "endTime",
                "queueTime",
                "callTime",
                "accepted",
                "missed",
                "abandoned",
                "answeredByAlias",
                "notHandledByAlias",
                "callerNumberMasked"
            };

        static readonly Dictionary<string, HashSet<FilterOp>> AllowedOpsByField =
            new(StringComparer.OrdinalIgnoreCase)
            {
                ["type"] = new() { FilterOp.Is, FilterOp.In, FilterOp.NotIn },
                ["callDirection"] = new() { FilterOp.Is, FilterOp.In },
                ["skill"] = new() { FilterOp.Is, FilterOp.StartsWith, FilterOp.In },
                ["endTime"] = new() { FilterOp.After, FilterOp.Before, FilterOp.Between, FilterOp.IsPresent },
                //["queueTime"] = new() { FilterOp.Between, FilterOp.Is, FilterOp.Gt, FilterOp.Gte, FilterOp.Lt, FilterOp.Lte }, // si quieres
                ["callTime"] = new() { FilterOp.Between },
                ["accepted"] = new() { FilterOp.Is },
                ["missed"] = new() { FilterOp.Is },
                ["abandoned"] = new() { FilterOp.Is },
                ["answeredByAlias"] = new() { FilterOp.IsPresent },
                ["notHandledByAlias"] = new() { FilterOp.IsPresent },
                ["callerNumberMasked"] = new() { FilterOp.IsPresent }
            };

        public static (bool ok, string? error, List<FieldFilter> filters, string? sort)
         ParseChargebeeStyle(HttpContext http)
        {
            var filters = new List<FieldFilter>();

            // sort_by[asc]=endTime o sort_by[desc]=endTime
            string? sort = null;
            if (http.Request.Query.TryGetValue("sort_by[asc]", out var asc))
                sort = $"{asc.ToString()}:asc";
            if (http.Request.Query.TryGetValue("sort_by[desc]", out var desc))
                sort = $"{desc.ToString()}:desc";

            if (sort is not null)
            {
                var parts = sort.Split(':', 2);
                var sortField = parts[0];
                if (!AllowedFields.Contains(sortField))
                    return (false, $"Invalid sort field '{sortField}'.", [], null);
            }
            else
            {
                sort = "endTime:desc"; // default
            }

            // Captura field[op]=value
            foreach (var kv in http.Request.Query)
            {
                var key = kv.Key;

                // ignora keys conocidas
                if (key.Equals("limit", StringComparison.OrdinalIgnoreCase) ||
                    key.Equals("offset", StringComparison.OrdinalIgnoreCase) ||
                    key.StartsWith("sort_by[", StringComparison.OrdinalIgnoreCase))
                    continue;

                var open = key.IndexOf('[');
                var close = key.IndexOf(']');
                if (open <= 0 || close <= open + 1) continue;

                var field = key[..open];
                var opRaw = key[(open + 1)..close];

                if (!AllowedFields.Contains(field))
                    return (false, $"Filter field '{field}' is not allowed.", [], null);

                if (!TryParseOp(opRaw, out var op))
                    return (false, $"Operator '{opRaw}' is not supported.", [], null);

                if (!AllowedOpsByField.TryGetValue(field, out var allowedOps) || !allowedOps.Contains(op))
                    return (false, $"Operator '{opRaw}' not allowed for field '{field}'.", [], null);

                var values = SplitValues(kv.Value.ToString(), op);
                filters.Add(new FieldFilter(field, op, values));
            }

            return (true, null, filters, sort);
        }

        static bool TryParseOp(string opRaw, out FilterOp op)
        {
            op = opRaw.ToLowerInvariant() switch
            {
                "is" => FilterOp.Is,
                "is_not" => FilterOp.IsNot,
                "in" => FilterOp.In,
                "not_in" => FilterOp.NotIn,
                "starts_with" => FilterOp.StartsWith,
                "after" => FilterOp.After,
                "before" => FilterOp.Before,
                "between" => FilterOp.Between,
                "is_present" => FilterOp.IsPresent,
                _ => default
            };
            return op != default || opRaw.Equals("is", StringComparison.OrdinalIgnoreCase);
        }

        static string[] SplitValues(string raw, FilterOp op)
        {
            if (op == FilterOp.IsPresent) return new[] { raw }; // "true"/"false"
                                                                // soporta "a,b,c" y también "a" simple
            return raw.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
        }

        public static string StableFilterString(List<FieldFilter> filters, string sort)
        {
            // determinístico: ordena y concatena
            var parts = filters
                .OrderBy(f => f.Field, StringComparer.OrdinalIgnoreCase)
                .ThenBy(f => f.Op.ToString(), StringComparer.OrdinalIgnoreCase)
                .Select(f => $"{f.Field}[{f.Op}]={string.Join(",", f.Values)}");

            return $"{sort}|{string.Join("&", parts)}";
        }

        public static IEnumerable<CallRecord> ApplyFilters(IEnumerable<CallRecord> src, List<FieldFilter> filters)
        {
            foreach (var f in filters)
                src = ApplyOne(src, f);
            return src;
        }

        public static IEnumerable<CallRecord> ApplyOne(IEnumerable<CallRecord> src, FieldFilter f) =>
            (f.Field.ToLowerInvariant(), f.Op) switch
            {
                ("type", FilterOp.Is) => src.Where(x => string.Equals(x.Type, f.Values[0], StringComparison.OrdinalIgnoreCase)),
                ("type", FilterOp.In) => src.Where(x => f.Values.Contains(x.Type, StringComparer.OrdinalIgnoreCase)),

                ("calldirection", FilterOp.Is) => src.Where(x => string.Equals(x.CallDirection, f.Values[0], StringComparison.OrdinalIgnoreCase)),

                ("skill", FilterOp.Is) => src.Where(x => string.Equals(x.Skill ?? "", f.Values[0], StringComparison.OrdinalIgnoreCase)),
                ("skill", FilterOp.StartsWith) => src.Where(x => (x.Skill ?? "").StartsWith(f.Values[0], StringComparison.OrdinalIgnoreCase)),

                ("endtime", FilterOp.After) => src.Where(x => x.EndTime > DateTimeOffset.Parse(f.Values[0])),
                ("endtime", FilterOp.Before) => src.Where(x => x.EndTime < DateTimeOffset.Parse(f.Values[0])),
                ("endtime", FilterOp.Between) => src.Where(x =>
                    x.EndTime >= DateTimeOffset.Parse(f.Values[0]) &&
                    x.EndTime <= DateTimeOffset.Parse(f.Values[1])),

                //("answeredbyalias", FilterOp.IsPresent) => ParseBool(f.Values[0]) ? src.Where(x => x.AnsweredByAlias is not null) : src.Where(x => x.AnsweredByAlias is null),

                _ => src // si no match, no filtra (o puedes devolver 400 si prefieres strict total)
            };

        static bool ParseBool(string s) => bool.TryParse(s, out var b) && b;

        public static IEnumerable<CallRecord> ApplySort(IEnumerable<CallRecord> src, string sort)
        {
            var (field, dir) = sort.Split(':', 2) switch
            {
                var a when a.Length == 2 => (a[0], a[1]),
                _ => ("endTime", "desc")
            };

            var desc = dir.Equals("desc", StringComparison.OrdinalIgnoreCase);

            return (field.ToLowerInvariant(), desc) switch
            {
                ("endtime", true) => src.OrderByDescending(x => x.EndTime).ThenByDescending(x => x.CallId),
                ("endtime", false) => src.OrderBy(x => x.EndTime).ThenBy(x => x.CallId),
                ("queuetime", true) => src.OrderByDescending(x => x.QueueTime).ThenByDescending(x => x.CallId),
                ("queuetime", false) => src.OrderBy(x => x.QueueTime).ThenBy(x => x.CallId),
                _ => src.OrderByDescending(x => x.EndTime).ThenByDescending(x => x.CallId)
            };
        }

        public static (List<CallRecord> Items, string? NextLastKey) PageByCursor(IEnumerable<CallRecord> ordered, string? lastKey, int take)
        {
            // LastKey = "{ticks}:{callId}"
            if (!string.IsNullOrWhiteSpace(lastKey))
            {
                var parts = lastKey.Split(':', 2);
                if (parts.Length == 2 && long.TryParse(parts[0], out var ticks))
                {
                    var lastTime = new DateTimeOffset(new DateTime(ticks, DateTimeKind.Utc));
                    var lastId = parts[1];

                    ordered = ordered.Where(x =>
                        x.EndTime < lastTime ||
                        (x.EndTime == lastTime && string.CompareOrdinal(x.CallId, lastId) < 0));
                }
            }

            var list = ordered.Take(take).ToList();

            string? next = null;
            if (list.Count == take)
            {
                var last = list[^1];
                next = $"{last.EndTime.UtcTicks}:{last.CallId}";
            }

            return (list, next);
        }


    }
}
