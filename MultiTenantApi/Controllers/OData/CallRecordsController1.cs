//using Microsoft.AspNetCore.Authorization;
//using Microsoft.AspNetCore.Mvc;
//using Microsoft.AspNetCore.OData.Deltas;
//using Microsoft.AspNetCore.OData.Query;
//using Microsoft.AspNetCore.OData.Query.Validator;
//using Microsoft.AspNetCore.OData.Results;
//using Microsoft.AspNetCore.OData.Routing.Controllers;
//using MultiTenantApi.Models;
//using MultiTenantApi.Security;
//using MultiTenantApi.Services;
//using System.Security.Claims;

//namespace MultiTenantApi.Controllers.OData
//{
//    [ApiController]
//    [Route("api/v1/odata/[controller]")]
//    public sealed class CallRecordsController1 : ODataController
//    {
//        private readonly IRawDataService _data;
//        private readonly ISyntheticIdService _synth;

//        public CallRecordsController1(IRawDataService data, ISyntheticIdService synth)
//        {
//            _data = data;
//            _synth = synth;
//        }

//        #region READ (GET)

//        /// <summary>
//        /// OData entry point:
//        /// - Supports $filter, $select, $orderby, $expand, $count, $top, $skip
//        /// - Returns IQueryable so OData can translate query options efficiently.
//        /// - ABAC: tenant scoping is enforced BEFORE query execution.
//        /// </summary>
//        [HttpGet]
//        [EnableQuery(
//            MaxTop = 200,
//            MaxExpansionDepth = 3,
//            AllowedQueryOptions =
//                AllowedQueryOptions.Select |
//                AllowedQueryOptions.Filter |
//                AllowedQueryOptions.OrderBy |
//                AllowedQueryOptions.Expand |
//                AllowedQueryOptions.Top |
//                AllowedQueryOptions.Skip |
//                AllowedQueryOptions.Count)]
//        [Authorize(AuthzPolicies.DocumentsReadPolicyName)]
//        public IActionResult Get(ODataQueryOptions<CallRecordODataDto> options)
//        {
//            var tenantId = User.FindFirstValue("tid");
//            if (string.IsNullOrWhiteSpace(tenantId))
//                return Forbid();

//            // IMPORTANT:
//            // Build an IQueryable over your data source.
//            // In a real implementation, this should be EF Core IQueryable from DbContext,
//            // not in-memory lists, to avoid loading everything in RAM.
//            var queryable = BuildTenantQueryable(tenantId);

//            // Enterprise hardening:
//            // Validate query options to prevent pathological queries.
//            ValidateOData(options);

//            return Ok(queryable);
//        }

//        /// <summary>
//        /// Single entity read: /CallRecords('id')
//        /// </summary>
//        [HttpGet("({key})")]
//        [EnableQuery]
//        [Authorize(AuthzPolicies.DocumentsReadPolicyName)]
//        public IActionResult Get([FromRoute] string key)
//        {
//            var tenantId = User.FindFirstValue("tid");
//            if (string.IsNullOrWhiteSpace(tenantId))
//                return Forbid();

//            var queryable = BuildTenantQueryable(tenantId)
//                .Where(x => x.Id == key);

//            return Ok(SingleResult.Create(queryable));
//        }

//        #endregion

//        #region CREATE (POST)

//        /// <summary>
//        /// Create a new call record (rare in exports, but included as CRUD example).
//        /// POST /api/v2/odata/CallRecords
//        /// </summary>
//        [HttpPost]
//        [Authorize(AuthzPolicies.ReportsReadPolicyName)] // In real life, create a "Write" policy
//        public IActionResult Post([FromBody] CallRecordODataDto input)
//        {
//            var tenantId = User.FindFirstValue("tid");
//            if (string.IsNullOrWhiteSpace(tenantId))
//                return Forbid();

//            // ABAC: force tenant binding server-side (never trust client).
//            input.TenantId = tenantId;

//            // TODO:
//            // Persist through a repository / DbContext.
//            // For demo: return Created.
//            return Created(input);
//        }

//        #endregion

//        #region UPDATE (PUT)

//        /// <summary>
//        /// Full update: replaces the resource.
//        /// PUT /CallRecords('id')
//        /// </summary>
//        [HttpPut("({key})")]
//        [Authorize(AuthzPolicies.ReportsReadPolicyName)]
//        public IActionResult Put([FromRoute] string key, [FromBody] CallRecordODataDto input)
//        {
//            var tenantId = User.FindFirstValue("tid");
//            if (string.IsNullOrWhiteSpace(tenantId))
//                return Forbid();

//            // ABAC: enforce tenant and key binding
//            input.TenantId = tenantId;
//            input.Id = key;

//            // TODO: Update in DB
//            return Updated(input);
//        }

//        #endregion

//        #region PARTIAL UPDATE (PATCH)

//        /// <summary>
//        /// Partial update: uses Delta<T> which is the OData-native PATCH mechanism.
//        /// PATCH /CallRecords('id')
//        /// </summary>
//        [HttpPatch("({key})")]
//        [Authorize(AuthzPolicies.ReportsReadPolicyName)]
//        public IActionResult Patch([FromRoute] string key, [FromBody] Delta<CallRecordODataDto> delta)
//        {
//            var tenantId = User.FindFirstValue("tid");
//            if (string.IsNullOrWhiteSpace(tenantId))
//                return Forbid();

//            // TODO:
//            // 1) Load existing entity from DB scoped by tenantId + key
//            // 2) Apply delta.Patch(entity)
//            // 3) Save changes
//            //
//            // delta.GetChangedPropertyNames() is also useful for auditing.
//            return StatusCode(StatusCodes.Status501NotImplemented, new
//            {
//                message = "PATCH demo endpoint. Implement persistence + delta apply."
//            });
//        }

//        #endregion

//        #region DELETE

//        /// <summary>
//        /// Delete a resource.
//        /// DELETE /CallRecords('id')
//        /// </summary>
//        [HttpDelete("({key})")]
//        [Authorize(AuthzPolicies.ReportsReadPolicyName)]
//        public IActionResult Delete([FromRoute] string key)
//        {
//            var tenantId = User.FindFirstValue("tid");
//            if (string.IsNullOrWhiteSpace(tenantId))
//                return Forbid();

//            // TODO: Delete in DB scoped by tenantId + key
//            return NoContent();
//        }

//        #endregion

//        #region Internals (Tenant Query + Validation)

//        private IQueryable<CallRecordODataDto> BuildTenantQueryable(string tenantId)
//        {
//            // Your existing service is "QueryAsync" which is paging-based and string-filter based.
//            // For OData, you want IQueryable from EF Core ideally.
//            //
//            // For demo purposes: translate your internal records into an IQueryable.
//            // Replace with DbContext.CallRecords.Where(x => x.TenantId == tenantId) in production.

//            var data = _data // you will adapt to real data source
//                .AsQueryableForOData(tenantId, _synth); // create an adapter extension (recommended)

//            return data;
//        }

//        private static void ValidateOData(ODataQueryOptions<CallRecordODataDto> options)
//        {
//            // Enterprise-grade query hardening:
//            // 1) Block $orderby on unindexed fields if using large datasets
//            // 2) Block contains() on huge text fields (expensive)
//            // 3) Block too many 'or' conditions (query explosion)
//            //
//            // OData has built-in validation via ODataValidationSettings, but you can also do custom rules.

//            var settings = new ODataValidationSettings
//            {
//                MaxTop = 200,
//                MaxExpansionDepth = 3
//            };

//            options.Validate(settings);
//        }

//        #endregion
//    }

//}
