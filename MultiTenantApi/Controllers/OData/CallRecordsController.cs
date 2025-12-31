using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.OData.Deltas;
using Microsoft.AspNetCore.OData.Formatter;
using Microsoft.AspNetCore.OData.Query;
using Microsoft.AspNetCore.OData.Query.Validator;
using Microsoft.AspNetCore.OData.Results;
using Microsoft.AspNetCore.OData.Routing.Controllers;
using MultiTenantApi.Models;
using MultiTenantApi.Security;
using MultiTenantApi.Services;
using System.Security.Claims;

namespace MultiTenantApi.Controllers.OData;

public sealed class CallRecordsController : ODataController
{
    private readonly IRawDataService _data;
    private readonly ISyntheticIdService _synth;

    public CallRecordsController(IRawDataService data, ISyntheticIdService synth)
    {
        _data = data;
        _synth = synth;
    }

    // GET /api/v1/odata/CallRecords?$filter=...&$select=...&$top=...
    [EnableQuery(
        MaxTop = 200,
        MaxExpansionDepth = 3,
        AllowedQueryOptions =
            AllowedQueryOptions.Select |
            AllowedQueryOptions.Filter |
            AllowedQueryOptions.OrderBy |
            AllowedQueryOptions.Expand |
            AllowedQueryOptions.Top |
            AllowedQueryOptions.Skip |
            AllowedQueryOptions.Count)]
    [Authorize(AuthzPolicies.ReportsReadPolicyName)]
    public IActionResult Get(ODataQueryOptions<CallRecordODataDto> options)
    {
        var tenantId = User.FindFirstValue("tid");
        if (string.IsNullOrWhiteSpace(tenantId))
            return Forbid();

        var queryable = _data.AsQueryableForOData(tenantId, _synth);

        ValidateOData(options);

        return Ok(queryable);
    }

    // GET /api/v1/odata/CallRecords('id')
    [EnableQuery]
    [Authorize(AuthzPolicies.ReportsReadPolicyName)]
    public IActionResult Get([FromODataUri] string key)
    {
        var tenantId = User.FindFirstValue("tid");
        if (string.IsNullOrWhiteSpace(tenantId))
            return Forbid();

        var queryable = _data.AsQueryableForOData(tenantId, _synth)
            .Where(x => x.Id == key);

        return Ok(SingleResult.Create(queryable));
    }

    // POST /api/v1/odata/CallRecords
    [Authorize(AuthzPolicies.ReportsReadPolicyName)]
    public IActionResult Post([FromBody] CallRecordODataDto input)
    {
        var tenantId = User.FindFirstValue("tid");
        if (string.IsNullOrWhiteSpace(tenantId))
            return Forbid();

        input.TenantId = tenantId;

        // TODO: persist
        return Created(input);
    }

    // PUT /api/v1/odata/CallRecords('id')
    [Authorize(AuthzPolicies.ReportsReadPolicyName)]
    public IActionResult Put([FromODataUri] string key, [FromBody] CallRecordODataDto input)
    {
        var tenantId = User.FindFirstValue("tid");
        if (string.IsNullOrWhiteSpace(tenantId))
            return Forbid();

        input.TenantId = tenantId;
        input.Id = key;

        // TODO: persist
        return Updated(input);
    }

    // PATCH /api/v1/odata/CallRecords('id')
    [Authorize(AuthzPolicies.ReportsReadPolicyName)]
    public IActionResult Patch([FromODataUri] string key, [FromBody] Delta<CallRecordODataDto> delta)
    {
        var tenantId = User.FindFirstValue("tid");
        if (string.IsNullOrWhiteSpace(tenantId))
            return Forbid();

        // TODO:
        // load entity scoped by tenantId + key
        // delta.Patch(entity)
        // save
        return StatusCode(StatusCodes.Status501NotImplemented, new
        {
            message = "PATCH demo endpoint. Implement persistence + delta apply."
        });
    }

    // DELETE /api/v1/odata/CallRecords('id')
    [Authorize(AuthzPolicies.ReportsReadPolicyName)]
    public IActionResult Delete([FromODataUri] string key)
    {
        var tenantId = User.FindFirstValue("tid");
        if (string.IsNullOrWhiteSpace(tenantId))
            return Forbid();

        // TODO: delete scoped by tenantId + key
        return NoContent();
    }

    private static void ValidateOData(ODataQueryOptions<CallRecordODataDto> options)
    {
        var settings = new ODataValidationSettings
        {
            MaxTop = 200,
            MaxExpansionDepth = 3
        };

        options.Validate(settings);
    }
}
