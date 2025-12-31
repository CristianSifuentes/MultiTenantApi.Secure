// ============================================================================
// Program.cs (Minimal APIs) — Enterprise-ready organization
// Notes:
// - This is a "clean & structured" re-organization of your existing Program.cs.
// - Comments are intentionally verbose and technical (architect-level).
// - All comments are in English as requested.
// - Regions are used to make navigation easy in Visual Studio.
// ============================================================================

#region Usings

using System.Diagnostics;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Threading.RateLimiting;

using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.HttpOverrides;
using Microsoft.AspNetCore.RateLimiting;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using Microsoft.OpenApi.Models;

using Mapster;
using MapsterMapper;

using Serilog;
using Serilog.Events;
using Serilog.Filters;

using MultiTenantApi.Common;
using MultiTenantApi.Infrastructure;
using MultiTenantApi.Mapping;
using MultiTenantApi.Middleware.High;
using MultiTenantApi.Middleware.Low;
using MultiTenantApi.Middleware.Medium;
using MultiTenantApi.Models;
using MultiTenantApi.Security;
using MultiTenantApi.Security.IdempotencyStore;
using MultiTenantApi.Security.ProblemDetails;
using MultiTenantApi.Services;
using MultiTenantApi.Services.CacheService;
using MultiTenantApi.Services.Filter;
using MultiTenantApi.Services.HMAC;
using MultiTenantApi.Services.HttpCache;
using MultiTenantApi.Services.JobStore;


using Microsoft.AspNetCore.OData;
using Microsoft.OData.ModelBuilder;

#endregion

#region Bootstrap

var builder = WebApplication.CreateBuilder(args);

#endregion

#region Logging (Serilog) — Structured + Secret-Safe

// Create an early bootstrap logger to capture startup failures.
// IMPORTANT: Do not log tokens/Authorization headers at any stage.
Log.Logger = new LoggerConfiguration()
    .ReadFrom.Configuration(builder.Configuration)
    .Enrich.FromLogContext()
    // Redaction enricher prevents accidental leakage of sensitive headers.
    // NOTE: In production, prefer resolving IHttpContextAccessor from DI (see DI region).
    .Enrich.With(new RedactSensitiveHeadersEnricher(new HttpContextAccessor()))
    .WriteTo.Console()
    .CreateLogger();

// Integrate Serilog into the hosting pipeline.
// This ensures all ASP.NET Core logs flow through Serilog.
builder.Host.UseSerilog((ctx, lc) =>
{
    lc.ReadFrom.Configuration(ctx.Configuration)
      .MinimumLevel.Override("Microsoft", LogEventLevel.Warning)
      .MinimumLevel.Override("Microsoft.AspNetCore", LogEventLevel.Warning)
      .Enrich.FromLogContext()
      .Enrich.WithProperty("service", "MultiTenantApi")
      .Enrich.WithProperty("env", ctx.HostingEnvironment.EnvironmentName)

      // Explicitly block common sensitive properties if someone adds them to logs.
      .Filter.ByExcluding(Matching.WithProperty<string>("RequestHeader_Authorization", _ => true))
      .Filter.ByExcluding(Matching.WithProperty<string>("RequestHeader_Cookie", _ => true))
      .Filter.ByExcluding(Matching.WithProperty<string>("Authorization", _ => true))

      // Defense-in-depth: if a Bearer token is ever serialized as a string, redact it.
      .Destructure.ByTransforming<string>(s =>
          s.Contains("Bearer ", StringComparison.OrdinalIgnoreCase) ? "[REDACTED]" : s)

      .WriteTo.Console();
});

#endregion

#region Security (JWT Claims Mapping)

// Keep Entra ID claims as-is (tid/scp/roles). Avoid legacy remapping to WS-Federation style claim types.
JwtSecurityTokenHandler.DefaultMapInboundClaims = false;

#endregion

#region Configuration (Options & Entra)

var azureAd = builder.Configuration.GetSection("AzureAd");

// In Entra ID multi-tenant APIs, you typically use:
// - "common" (consumer + org accounts), or
// - "organizations", or
// - a specific tenantId.
// Use with caution based on your product’s tenancy model.
var instance = azureAd["Instance"] ?? "https://login.microsoftonline.com/";
var tenantId = azureAd["TenantId"] ?? "common";
var authority = $"{instance.TrimEnd('/')}/{tenantId}/v2.0";

// Audience is typically api://{API_CLIENT_ID} (recommended).
var audience =
    azureAd["Audience"] ??
    throw new InvalidOperationException("AzureAd:Audience is required (e.g., api://{API_CLIENT_ID}).");

// Options binding (strongly typed config).
builder.Services.Configure<SyntheticIdOptions>(builder.Configuration.GetSection("SyntheticId"));
builder.Services.Configure<TokenHardeningOptions>(builder.Configuration.GetSection("TokenHardening"));
builder.Services.Configure<RateLimitingEnterpriseOptions>(builder.Configuration.GetSection("RateLimitingEnterprise"));
builder.Services.Configure<DeprecationPolicyOptions>(builder.Configuration.GetSection("DeprecationPolicy"));

// Local-only cache implementation for dev.
// Production recommendation: switch to Redis (IDistributedCache) to support scaling.
builder.Services.AddDistributedMemoryCache();

#endregion

#region OData (Enterprise Query Surface)



builder.Services
    .AddControllers()
    .AddOData(opt =>
    {
        // EDM model: what the service exposes
        var edmBuilder = new ODataConventionModelBuilder();

        // EntitySet name MUST match controller name convention (CustomersController => Customers)
        edmBuilder.EntitySet<CallRecordODataDto>("CallRecords");

        // Route: /api/v1/odata/...
        opt.AddRouteComponents("api/v1/odata", edmBuilder.GetEdmModel())
           .Select()
           .Filter()
           .OrderBy()
           .Expand()
           .Count()
           .SetMaxTop(200); // hard limit (defense-in-depth)
    });



#endregion


#region Authentication (JWT Bearer) — Hardened Validation

builder.Services
    .AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
    .AddJwtBearer(options =>
    {
        options.Authority = authority;
        options.RequireHttpsMetadata = true;

        // Read hardening options once (fallback to defaults).
        var hardening =
            builder.Configuration.GetSection("TokenHardening").Get<TokenHardeningOptions>() ?? new();

        options.TokenValidationParameters = new TokenValidationParameters
        {
            // Require cryptographic integrity and expiration.
            RequireSignedTokens = true,
            ValidateIssuerSigningKey = true,
            RequireExpirationTime = true,

            // Issuer must be from allow-list logic (multi-tenant safe).
            ValidateIssuer = true,
            IssuerValidator = TenantAllowListIssuerValidator.Build(builder.Configuration),

            // Strict audience validation to prevent token substitution across APIs.
            ValidateAudience = true,
            ValidAudiences = new[]
            {
                audience,
                azureAd["ClientId"] // optional fallback, if you also accept clientId as aud (be deliberate).
            }
            .Where(x => !string.IsNullOrWhiteSpace(x))
            .ToArray(),

            // Enforce exp/nbf with minimal skew to tolerate clock drift.
            ValidateLifetime = true,
            ClockSkew = TimeSpan.FromSeconds(Math.Clamp(hardening.ClockSkewSeconds, 0, 120)),

            // Algorithm allow-list. For Entra access tokens RS256 is standard; ES256 can be enabled if applicable.
            ValidAlgorithms = new[]
            {
                SecurityAlgorithms.RsaSha256,   // RS256
                SecurityAlgorithms.EcdsaSha256  // ES256 (optional)
            },

            // Keep claims aligned with Entra.
            NameClaimType = "name",
            RoleClaimType = "roles",
        };

        // Key rollover safe (kid rotates).
        options.RefreshOnIssuerKeyNotFound = true;

        // Avoid persisting tokens server-side.
        options.SaveToken = false;

        options.Events = new JwtBearerEvents
        {
            OnTokenValidated = async ctx =>
            {
                // Defense-in-depth: explicitly reject alg=none and unknown algorithms.
                if (ctx.SecurityToken is JwtSecurityToken jwt)
                {
                    var alg = jwt.Header.Alg;

                    if (string.Equals(alg, "none", StringComparison.OrdinalIgnoreCase))
                    {
                        ctx.Fail("Rejected unsigned JWT (alg=none).");
                        return;
                    }

                    if (alg is null ||
                        !(alg.Equals("RS256", StringComparison.OrdinalIgnoreCase) ||
                          alg.Equals("ES256", StringComparison.OrdinalIgnoreCase)))
                    {
                        ctx.Fail($"Rejected JWT with unsupported alg='{alg}'.");
                        return;
                    }
                }

                // Optional token replay / revocation checks using jti.
                // NOTE: Entra access tokens may not always carry "jti"; treat it as best-effort unless you enforce it.
                var revocation = ctx.HttpContext.RequestServices.GetRequiredService<ITokenRevocationStore>();
                var hard = ctx.HttpContext.RequestServices.GetRequiredService<IOptions<TokenHardeningOptions>>().Value;

                if (hard.EnableJtiReplayProtection)
                {
                    var jti = ctx.Principal?.FindFirstValue(JwtRegisteredClaimNames.Jti);

                    if (!string.IsNullOrWhiteSpace(jti))
                    {
                        // 1) If revoked -> block.
                        if (await revocation.IsRevokedAsync(jti, ctx.HttpContext.RequestAborted))
                        {
                            ctx.Fail("Token has been revoked.");
                            return;
                        }

                        // 2) Replay detection -> block if "jti" observed before.
                        // Disable this if your usage model expects reusing the same access token frequently.
                        var replayOk = await revocation.TryMarkSeenAsync(
                            jti,
                            TimeSpan.FromMinutes(hard.JtiCacheMinutes),
                            ctx.HttpContext.RequestAborted);

                        if (!replayOk)
                        {
                            ctx.Fail("Token replay detected (jti reused).");
                            return;
                        }
                    }
                }
            },

            OnAuthenticationFailed = ctx =>
            {
                // Do not leak details; store a safe reason for ProblemDetails middleware.
                var reason =
                    ctx.Exception is SecurityTokenExpiredException ? "token_expired" :
                    ctx.Exception is SecurityTokenInvalidSignatureException ? "invalid_signature" :
                    ctx.Exception is SecurityTokenInvalidAudienceException ? "invalid_audience" :
                    ctx.Exception is SecurityTokenInvalidIssuerException ? "invalid_issuer" :
                    ctx.Exception is SecurityTokenException ? "token_invalid" :
                    "auth_failed";

                ctx.HttpContext.Items["auth_fail_reason"] = reason;
                ctx.HttpContext.Items["auth_failed"] = true;

                return Task.CompletedTask;
            },

            OnChallenge = ctx =>
            {
                // Challenge occurs on 401, usually when no/invalid token.
                ctx.HttpContext.Items["auth_fail_reason"] ??= "challenge";
                return Task.CompletedTask;
            },

            OnForbidden = ctx =>
            {
                // Forbidden occurs on 403, usually when token valid but lacks required permission.
                ctx.HttpContext.Items["auth_fail_reason"] ??= "forbidden_policy";
                return Task.CompletedTask;
            }
        };
    });

#endregion

#region Authorization (Policies) — Scopes + App Roles

builder.Services.AddAuthorization(options =>
{
    // Centralized configuration: keep policy definitions in one place.
    AuthzPolicies.Configure(options, builder.Configuration);

    // Example "role-only" policy (use sparingly; scopes/app roles are usually better in multi-tenant APIs).
    options.AddPolicy("AdminOnly", p =>
    {
        p.RequireAuthenticatedUser();
        p.RequireRole("Admin");
    });
});

#endregion

#region Rate Limiting — Global + Endpoint Policies

builder.Services.AddRateLimiter(o =>
{
    // Global 429 shape should be consistent and RFC7807 compliant.
    o.RejectionStatusCode = StatusCodes.Status429TooManyRequests;

    o.OnRejected = async (context, ct) =>
    {
        var http = context.HttpContext;

        http.Response.StatusCode = StatusCodes.Status429TooManyRequests;
        http.Response.ContentType = "application/problem+json";

        var result = Results.Problem(
            title: "Too many requests.",
            statusCode: StatusCodes.Status429TooManyRequests,
            detail: "Slow down and retry later.",
            extensions: new Dictionary<string, object?>
            {
                ["errorCode"] = ApiErrorCodes.RateLimited,
                ["traceId"] = http.TraceIdentifier,
                ["correlationId"] = http.Items.TryGetValue("correlation_id", out var cid) ? cid : null
            });

        await result.ExecuteAsync(http);
    };

    // GLOBAL limiter: selects best identity key: user -> client -> ip.
    o.GlobalLimiter = PartitionedRateLimiter.Create<HttpContext, string>(ctx =>
    {
        // Prefer a stable authenticated identity.
        var key =
            RateLimitKeyFactory.GetUserKey(ctx) != "user:anonymous"
                ? RateLimitKeyFactory.GetUserKey(ctx)
                : RateLimitKeyFactory.GetClientKey(ctx) != "client:anonymous"
                    ? RateLimitKeyFactory.GetClientKey(ctx)
                    : RateLimitKeyFactory.GetIpFallback(ctx);

        var limits = ctx.RequestServices.GetRequiredService<IOptions<RateLimitOptions>>().Value;

        return RateLimitPartition.GetTokenBucketLimiter(
            partitionKey: key,
            factory: _ => new TokenBucketRateLimiterOptions
            {
                // Burst capacity.
                TokenLimit = Math.Max(1, limits.BurstPer10Seconds),

                // Sustained throughput.
                TokensPerPeriod = Math.Max(1, limits.PerIdentityPerMinute),
                ReplenishmentPeriod = TimeSpan.FromMinutes(1),

                // For APIs, fail fast by default (no queue).
                QueueLimit = 0,
                QueueProcessingOrder = QueueProcessingOrder.OldestFirst,

                AutoReplenishment = true
            });
    });

    // Tenant fairness policy for heavy endpoints (exports).
    o.AddPolicy("exports-tenant", ctx =>
    {
        var opt = ctx.RequestServices.GetRequiredService<IOptions<RateLimitingEnterpriseOptions>>().Value;
        var key = RateLimitKeyFactory.GetTenantKey(ctx);

        return RateLimitPartition.GetFixedWindowLimiter(
            partitionKey: key,
            factory: _ => new FixedWindowRateLimiterOptions
            {
                PermitLimit = Math.Max(1, opt.Exports.PerTenantPerMinute),
                Window = TimeSpan.FromMinutes(1),
                QueueLimit = 0,
                AutoReplenishment = true
            });
    });

    // Tenant fairness policy for search endpoints.
    o.AddPolicy("search-tenant", ctx =>
    {
        var opt = ctx.RequestServices.GetRequiredService<IOptions<RateLimitingEnterpriseOptions>>().Value;
        var key = RateLimitKeyFactory.GetTenantKey(ctx);

        return RateLimitPartition.GetFixedWindowLimiter(
            partitionKey: key,
            factory: _ => new FixedWindowRateLimiterOptions
            {
                PermitLimit = Math.Max(1, opt.Search.PerTenantPerMinute),
                Window = TimeSpan.FromMinutes(1),
                QueueLimit = 0,
                AutoReplenishment = true
            });
    });

    // Login anti-abuse (credential stuffing mitigation) — IP-based limiter.
    o.AddPolicy("login", ctx =>
    {
        var opt = ctx.RequestServices.GetRequiredService<IOptions<RateLimitingEnterpriseOptions>>().Value;
        var ip = RateLimitKeyFactory.GetIpFallback(ctx);

        return RateLimitPartition.GetFixedWindowLimiter(
            partitionKey: ip,
            factory: _ => new FixedWindowRateLimiterOptions
            {
                PermitLimit = Math.Max(1, opt.Login.PerIpPerMinute),
                Window = TimeSpan.FromMinutes(1),
                QueueLimit = 0,
                AutoReplenishment = true
            });
    });

    // Enterprise-grade client-specific limiter (useful for contractual client rate tiers).
    o.AddPolicy("exports-client", ctx =>
    {
        var opt = ctx.RequestServices.GetRequiredService<IOptions<RateLimitingEnterpriseOptions>>().Value;
        var key = RateLimitKeyFactory.GetClientKey(ctx);

        return RateLimitPartition.GetFixedWindowLimiter(
            partitionKey: key,
            factory: _ => new FixedWindowRateLimiterOptions
            {
                PermitLimit = Math.Max(1, opt.Exports.PerClientPerMinute),
                Window = TimeSpan.FromMinutes(1),
                QueueLimit = 0,
                AutoReplenishment = true
            });
    });
});

#endregion

#region Swagger (OpenAPI) — Versioned docs + JWT support

builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen(o =>
{
    o.SwaggerDoc("v1", new() { Title = "MultiTenantApi.Secure", Version = "v1" });
    o.SwaggerDoc("v2", new() { Title = "MultiTenantApi.Secure", Version = "v2" });
    o.SwaggerDoc("v3", new() { Title = "MultiTenantApi.Secure", Version = "v3" });

    o.AddSecurityDefinition("bearerAuth", new OpenApiSecurityScheme
    {
        Type = SecuritySchemeType.Http,
        Scheme = "bearer",
        BearerFormat = "JWT",
        Description = "Azure AD / Entra ID Bearer token"
    });

    o.AddSecurityRequirement(new OpenApiSecurityRequirement
    {
        {
            new OpenApiSecurityScheme
            {
                Reference = new OpenApiReference
                {
                    Type = ReferenceType.SecurityScheme,
                    Id = "bearerAuth"
                }
            },
            Array.Empty<string>()
        }
    });
});

#endregion

#region Mapping (Mapster)

// Register mapping configuration once at startup.
MapsterConfig.RegisterMaps();

#endregion

#region Dependency Injection (Services + Middleware)

// Mapster core services.
builder.Services.AddSingleton(TypeAdapterConfig.GlobalSettings);
builder.Services.AddSingleton<IMapper, ServiceMapper>();

// Domain services.
builder.Services.AddSingleton<ISyntheticIdService, SyntheticIdService>();
builder.Services.AddSingleton<IRawDataService, InMemoryRawDataService>();
builder.Services.AddSingleton<ICallRecordService, InMemoryCallRecordService>();

// Security stores.
builder.Services.AddSingleton<ITokenRevocationStore, DistributedTokenRevocationStore>();
builder.Services.AddSingleton<IIdempotencyStore, DistributedIdempotencyStore>();

// Enterprise cursor protection (HMAC signed cursor tokens).
builder.Services.AddSingleton<ICursorProtector, HmacCursorProtector>();

// Cache abstraction (in-memory or distributed behind an interface).
builder.Services.AddSingleton<IApiCache, ApiCache>();

// Jobs (async export workflow).
builder.Services.AddSingleton<IJobQueue, InMemoryJobQueue>();
builder.Services.AddSingleton<IJobStore, DistributedJobStore>();
builder.Services.AddHostedService<ExportWorker>();

// Middleware registrations (as services only when they need DI).
builder.Services.AddSingleton<TokenAgeGuardMiddleware>();
builder.Services.AddSingleton<BlockApiKeyOnSensitiveRoutesMiddleware>();
builder.Services.AddSingleton<RequestLimitsMiddleware>();
builder.Services.AddSingleton<WafSignalsMiddleware>();
builder.Services.AddSingleton<DenySecretsInUrlMiddleware>();
builder.Services.AddSingleton<BlockSensitiveQueryStringMiddleware>();
builder.Services.AddSingleton<IdempotencyMiddleware>();
builder.Services.AddSingleton<AuthProblemDetailsMiddleware>();
builder.Services.AddSingleton<ApiVersioningMiddleware>();
builder.Services.AddSingleton<DeprecationHeadersMiddleware>();
builder.Services.AddSingleton<ApiVersionTelemetryMiddleware>();
builder.Services.AddSingleton<RequestTelemetryMiddleware>();
builder.Services.AddSingleton<SecuritySignalsMiddleware>();

#endregion

#region Build App

var app = builder.Build();

#endregion

#region API Version Groups (Route-based)

var api = app.MapGroup("/api");

var v1 = api.MapGroup("/v1")
    .WithTags("v1")
    .WithOpenApi();

var v2 = api.MapGroup("/v2")
    .WithTags("v2")
    .WithOpenApi();

var v3 = api.MapGroup("/v3")
    .WithTags("v3")
    .WithOpenApi();

var v4 = api.MapGroup("/v4")
    .WithTags("v4")
    .WithOpenApi();

#endregion

#region Reverse Proxy Support (Forwarded Headers)

// Behind Azure Front Door / App Gateway / Nginx / APIM, ensure we trust proxy forwarding.
// Production recommendation: configure KnownProxies/KnownNetworks to prevent spoofing.
app.UseForwardedHeaders(new ForwardedHeadersOptions
{
    ForwardedHeaders = ForwardedHeaders.XForwardedFor | ForwardedHeaders.XForwardedProto
});

#endregion

#region Global Error Handling (ProblemDetails)

// Centralized exception handler endpoint; do not leak stack traces to clients.
app.UseExceptionHandler("/error");

// Enforce HSTS (only meaningful on HTTPS).
app.UseHsts();

#endregion

#region Security Middleware (Pre-Auth)

// Enforce HTTPS at application level (defense-in-depth).
app.UseMiddleware<EnforceHttpsMiddleware>();

// Add standard security headers (X-Content-Type-Options, X-Frame-Options, etc.).
app.UseMiddleware<SecurityHeadersMiddleware>();

// Correlation ID for distributed tracing (logs + metrics + support).
app.UseMiddleware<CorrelationIdMiddleware>();

// Minimal audit trail (request->response) with token/PII-safe logging.
app.UseMiddleware<AuditMiddleware>();

// Block weak auth patterns on sensitive routes (e.g., API keys where JWT is required).
app.UseMiddleware<BlockApiKeyOnSensitiveRoutesMiddleware>();

// Request hardening (payload size, method restrictions, etc.). Not a WAF replacement.
app.UseMiddleware<RequestLimitsMiddleware>();

// WAF-like signal extraction (bot hints, anomaly scoring, etc.).
app.UseMiddleware<WafSignalsMiddleware>();

// Prevent secrets embedded in URL path/querystring (common proxy logging leak).
app.UseMiddleware<DenySecretsInUrlMiddleware>();
app.UseMiddleware<BlockSensitiveQueryStringMiddleware>();

// Idempotency enforcement (POST/PUT/PATCH) to protect from retries and double-processing.
app.UseMiddleware<IdempotencyMiddleware>();

// Optional internal versioning strategy (e.g., header-based).
app.UseMiddleware<ApiVersioningMiddleware>();

// Telemetry signals for version usage, tenant/client distribution, etc.
app.UseMiddleware<ApiVersionTelemetryMiddleware>();

// Request-level telemetry (latency, size, status, tenant/client tags).
app.UseMiddleware<RequestTelemetryMiddleware>();

// Security signals middleware (attack heuristics, suspicious patterns, etc.).
app.UseMiddleware<SecuritySignalsMiddleware>();

#endregion


#region Swagger UI

app.UseSwagger();
app.UseSwaggerUI(c =>
{
    c.SwaggerEndpoint("/swagger/v1/swagger.json", "MultiTenantApi.Secure v1");
    c.SwaggerEndpoint("/swagger/v2/swagger.json", "MultiTenantApi.Secure v2");
});

#endregion

#region AuthN / AuthZ

// Rate limiter should run before auth to reduce load under attack.
app.UseRateLimiter();

// Authentication populates HttpContext.User.
app.UseAuthentication();

// Token age guard must run AFTER authentication so claims are available.
app.UseMiddleware<TokenAgeGuardMiddleware>();

// Authorization enforces policies/scopes/roles.
app.UseAuthorization();

// Normalizes auth failures into consistent ProblemDetails responses.
app.UseMiddleware<AuthProblemDetailsMiddleware>();

#region OData
// OData uses controllers; make sure controller endpoints are mapped.
app.MapControllers();
#endregion

#endregion

#region Serilog Request Logging (Enrichment)

// Structured request logging for diagnostics.
// IMPORTANT: Do not add headers/body here; keep it safe.
app.UseSerilogRequestLogging(opts =>
{
    opts.EnrichDiagnosticContext = (diag, http) =>
    {
        diag.Set("TraceId", http.TraceIdentifier);

        if (http.Items.TryGetValue("correlation_id", out var cid))
            diag.Set("CorrelationId", cid);

        var tid = http.User?.FindFirstValue("tid");
        if (!string.IsNullOrWhiteSpace(tid)) diag.Set("TenantId", tid);

        var azp = http.User?.FindFirstValue("azp") ?? http.User?.FindFirstValue("appid");
        if (!string.IsNullOrWhiteSpace(azp)) diag.Set("ClientAppId", azp);

        diag.Set("Path", http.Request.Path.Value);
        diag.Set("Method", http.Request.Method);
    };

    // Reduce noise from health checks.
    opts.GetLevel = (ctx, _, ex) =>
        ctx.Request.Path.StartsWithSegments("/health") ? LogEventLevel.Verbose :
        ex is not null ? LogEventLevel.Error :
        LogEventLevel.Information;
});

#endregion


#region Debug
app.MapGet("/__debug/endpoints", (IEnumerable<EndpointDataSource> sources) =>
{
    var endpoints = sources.SelectMany(s => s.Endpoints)
        .Select(e => e.DisplayName)
        .OrderBy(x => x)
        .ToList();

    return Results.Ok(endpoints);
}).AllowAnonymous();
#endregion

#region Error Endpoint (/error) — RFC7807

app.MapGet("/error", (HttpContext ctx) =>
{
    // Always return safe, consistent error shapes.
    // Use TraceId/CorrelationId to correlate server logs.
    return Results.Problem(
        title: "An unexpected error occurred.",
        statusCode: StatusCodes.Status500InternalServerError,
        extensions: new Dictionary<string, object?>
        {
            ["traceId"] = ctx.TraceIdentifier,
            ["errorCode"] = "internal_error"
        });
}).ExcludeFromDescription();

#endregion

#region Endpoints (V1) — Core

// ============================================================================
// V1: Reports (Call Records) — Safe projection + ABAC tenant scoping
// ============================================================================

v1.MapGet("/reports/call-records", async (
    HttpContext http,
    [AsParameters] RawQuery q,
    IRawDataService dataSvc,
    ISyntheticIdService synth,
    ClaimsPrincipal user) =>
{
    // ABAC enforcement: tenant must exist.
    // This is a deny-by-default security rule.
    var tenant = TenantContextFactory.From(user);
    if (string.IsNullOrWhiteSpace(tenant.TenantId))
        return Results.Forbid();

    // Always clamp limits to prevent resource exhaustion (OWASP API4).
    var take = Math.Clamp(q.Limit ?? 100, 1, 100);

    // Data access must always be scoped by tenantId in the data layer.
    var page = await dataSvc.QueryAsync(
        tenant.TenantId,
        q.Filter,
        q.NextPageToken,
        take,
        http.RequestAborted);

    // Never return raw domain entities directly.
    // Always project to a safe "API shape" to prevent data over-exposure (OWASP API3/API9).
    var items = page.Items.Select(r =>
    {
        var shape = FieldProjector.ToApiShape(r, synth);
        return shape;
    });

    return Results.Ok(new
    {
        items,
        page = new
        {
            limit = take,
            nextPageToken = page.NextToken,
            count = page.Items.Count
        }
    });
})
.RequireRateLimiting("exports-tenant")
.RequireAuthorization(AuthzPolicies.DocumentsReadPolicyName)
.Produces(StatusCodes.Status200OK)
.ProducesProblem(StatusCodes.Status401Unauthorized)
.ProducesProblem(StatusCodes.Status403Forbidden)
.ProducesProblem(StatusCodes.Status429TooManyRequests)
.WithOpenApi();

// ============================================================================
// V1: Health
// ============================================================================

v1.MapGet("/health", () => Results.Ok(new { status = "ok", utc = DateTimeOffset.UtcNow }))
  .AllowAnonymous()
  .WithOpenApi();

// ============================================================================
// V1: WhoAmI — Debug endpoint to inspect claims (protect as needed)
// ============================================================================

v1.MapGet("/whoami", (ClaimsPrincipal user) =>
{
    var tid = user.FindFirstValue("tid");
    var oid = user.FindFirstValue("oid");
    var upn = user.FindFirstValue("preferred_username") ?? user.FindFirstValue(ClaimTypes.Upn);
    var scopes = user.FindFirstValue("scp");
    var roles = user.FindAll("roles").Select(r => r.Value).ToArray();
    var azp = user.FindFirstValue("azp") ?? user.FindFirstValue("appid");

    return Results.Ok(new
    {
        tenantId = tid,
        objectId = oid,
        user = user.Identity?.Name,
        preferredUsername = upn,
        clientAppId = azp,
        scp = scopes,
        roles
    });
})
.RequireAuthorization()
.WithOpenApi();

// ============================================================================
// V1: Documents + Reports — Sample secure endpoints
// ============================================================================

v1.MapGet("/documents", (ClaimsPrincipal user) =>
{
    var tid = user.FindFirstValue("tid");
    return Results.Ok(new
    {
        tenantId = tid,
        items = new[]
        {
            new { id = 1, title = "Entra Multi-tenant 101", classification = "Public" },
            new { id = 2, title = "Scopes vs App Roles", classification = "Internal" }
        }
    });
})
.RequireAuthorization(AuthzPolicies.DocumentsReadPolicyName)
.WithOpenApi();

v1.MapGet("/reports", (ClaimsPrincipal user) =>
{
    var tid = user.FindFirstValue("tid");
    return Results.Ok(new
    {
        tenantId = tid,
        generatedAtUtc = DateTimeOffset.UtcNow,
        items = new[]
        {
            new { id = "RPT-001", title = "Monthly Usage", severity = "Info" },
            new { id = "RPT-002", title = "Security Audit", severity = "High" }
        }
    });
})
.RequireAuthorization(AuthzPolicies.ReportsReadPolicyName)
.WithOpenApi();

#endregion

#region Endpoints (V1) — Metadata + Search

// ============================================================================
// Metadata endpoint — describes exportable fields + sample payload
// ============================================================================

v1.MapGet("/export/metadata/call-records", async (
    ICallRecordService svc,
    IMapper mapper,
    CancellationToken ct) =>
{
    var fields = ApiMetadataBuilder.BuildFor<CallRecord>();

    // Always map to a safe DTO (masking + synthetic IDs).
    var sampleDomain = await svc.GetSampleAsync(ct);
    var sampleExport = mapper.Map<List<CallRecordExportDto>>(sampleDomain);

    var response = new EntityMetadataResponse<CallRecordExportDto>(
        EntityName: "CallRecord",
        Version: "v1",
        Fields: fields,
        Sample: sampleExport);

    return Results.Ok(response);
})
.RequireRateLimiting("exports-tenant")
.RequireAuthorization(AuthzPolicies.ReportsReadPolicyName)
.WithOpenApi();

// ============================================================================
// Search endpoint — ABAC tenant + strict validation + safe preview
// ============================================================================

v1.MapGet("/search", async (
    HttpContext http,
    [AsParameters] SearchQuery q,
    ClaimsPrincipal user,
    IRawDataService dataSvc,
    ISyntheticIdService synth) =>
{
    var tenant = TenantContextFactory.From(user);
    if (string.IsNullOrWhiteSpace(tenant.TenantId))
        return Results.Forbid();

    // Validate BEFORE touching the data layer (cheap rejection).
    var validation = SearchQueryValidator.Validate(q);
    if (!validation.ok)
    {
        return Results.BadRequest(new
        {
            error = "invalid_query",
            message = validation.error,
            traceId = http.TraceIdentifier
        });
    }

    var take = Math.Clamp(q.Limit ?? 25, 1, 100);

    var page = await dataSvc.SearchAsync(
        tenantId: tenant.TenantId,
        query: q.Query!,
        channels: q.Channels,
        fromUtc: q.FromUtc,
        toUtc: q.ToUtc,
        nextToken: q.NextPageToken,
        take: take,
        ct: http.RequestAborted);

    // Always project output into a safe response model.
    var items = page.Items.Select(r => new Dictionary<string, object?>
    {
        ["syntheticId"] = synth.Create("raw", r.InternalId.ToString("N")),
        ["createdAt"] = r.CreatedAt,
        ["channel"] = r.Channel,
        ["textPreview"] = SearchQueryValidator.SafePreview(r.Text, maxLen: 160),
        ["syntheticUserId"] = string.IsNullOrWhiteSpace(r.UserInternalId) ? null : synth.Create("user", r.UserInternalId)
    });

    return Results.Ok(new
    {
        tenantId = tenant.TenantId,
        query = new
        {
            q = q.Query,
            channels = q.Channels,
            fromUtc = q.FromUtc,
            toUtc = q.ToUtc,
            limit = take
        },
        items,
        page = new
        {
            nextPageToken = page.NextToken,
            count = page.Items.Count
        }
    });
})
.RequireRateLimiting("search-tenant")
.RequireAuthorization(AuthzPolicies.ReportsReadPolicyName)
.WithOpenApi();

#endregion

#region Endpoints (V1) — Jobs + Exports + Token Revocation

// ============================================================================
// Orders endpoint — example "write" endpoint (idempotency middleware should protect).
// ============================================================================

v1.MapPost("/orders", async (
    CreateOrderRequest req,
    CancellationToken ct) =>
{
    // Input validation must be explicit and cheap.
    if (string.IsNullOrWhiteSpace(req.ProductId) || req.ProductId.Length > 64)
        return Results.BadRequest(new { error = "invalid_product" });

    if (req.Quantity < 1 || req.Quantity > 100)
        return Results.BadRequest(new { error = "invalid_quantity" });

    // TODO: Persist deterministically when idempotency key is used.
    var orderId = Guid.NewGuid().ToString("N");

    return Results.Created($"/api/v1/orders/{orderId}", new
    {
        id = orderId,
        productId = req.ProductId,
        quantity = req.Quantity
    });
})
.RequireAuthorization()
.WithOpenApi();

// ============================================================================
// Start export job — returns 202 Accepted + job status URL.
// ============================================================================

v1.MapPost("/exports/raw-records", async (
    HttpContext http,
    StartExportRequest body,
    IJobQueue queue,
    IJobStore store,
    ClaimsPrincipal user) =>
{
    var tenant = TenantContextFactory.From(user);
    if (string.IsNullOrWhiteSpace(tenant.TenantId))
        return Results.Forbid();

    // Early validation before queueing work.
    var take = Math.Clamp(body.Limit ?? 100, 1, 1000);
    var v = RawQueryValidator.Validate(body.Filter, body.NextPageToken, take);
    if (!v.ok)
        return Results.BadRequest(new { error = "invalid_query", message = v.error });

    var jobId = Guid.NewGuid().ToString("N");
    var ttl = TimeSpan.FromHours(2);

    var job = new JobInfo(
        JobId: jobId,
        TenantId: tenant.TenantId,
        Kind: "export:raw-data",
        State: JobState.Queued,
        CreatedUtc: DateTimeOffset.UtcNow,
        StartedUtc: null,
        CompletedUtc: null,
        ResultLocation: null,
        Error: null);

    await store.SetAsync(job, ttl, http.RequestAborted);

    await queue.EnqueueAsync(
        new JobMessage(jobId, tenant.TenantId, job.Kind, body, user),
        http.RequestAborted);

    var statusUrl = $"/jobs/{jobId}";
    var resultUrl = $"/exports/raw-data/{jobId}";

    http.Response.Headers.Location = statusUrl;
    return Results.Accepted(statusUrl, new StartJobResponse(jobId, statusUrl, resultUrl));
})
.RequireAuthorization(AuthzPolicies.ReportsReadPolicyName)
.RequireRateLimiting("exports-tenant")
.WithOpenApi();

// ============================================================================
// Job status — ABAC protected (job must belong to tenant).
// ============================================================================

v1.MapGet("/jobs/{id}", async (
    string id,
    HttpContext http,
    IJobStore store,
    ClaimsPrincipal user) =>
{
    var tenantId = user.FindFirstValue("tid");
    if (string.IsNullOrWhiteSpace(tenantId))
        return Results.Forbid();

    var job = await store.GetAsync(id, http.RequestAborted);
    if (job is null)
        return Results.NotFound();

    if (!string.Equals(job.TenantId, tenantId, StringComparison.Ordinal))
        return Results.Forbid();

    return Results.Ok(job);
})
.RequireAuthorization()
.WithOpenApi();

// ============================================================================
// Export download — ABAC + state machine safe handling.
// ============================================================================

v1.MapGet("/exports/raw-data/{jobId}", async (
    string jobId,
    HttpContext http,
    IJobStore store,
    ClaimsPrincipal user) =>
{
    var tenantId = user.FindFirstValue("tid");
    if (string.IsNullOrWhiteSpace(tenantId))
        return Results.Forbid();

    var job = await store.GetAsync(jobId, http.RequestAborted);
    if (job is null)
        return Results.NotFound();

    if (!string.Equals(job.TenantId, tenantId, StringComparison.Ordinal))
        return Results.Forbid();

    if (job.State is JobState.Queued or JobState.Running)
        return Results.Accepted($"/jobs/{jobId}", new { status = job.State.ToString() });

    if (job.State == JobState.Failed)
        return Results.Problem(title: "Export failed", detail: job.Error, statusCode: 500);

    if (job.State == JobState.Canceled)
        return Results.Problem(title: "Export canceled", statusCode: 409);

    // Production recommendation: stream from Blob Storage, not in-memory.
    return Results.Ok(new { message = "Would download from storage", job.ResultLocation });
})
.RequireAuthorization(AuthzPolicies.ReportsReadPolicyName)
.WithOpenApi();

// ============================================================================
// Token revocation endpoint — secure admin endpoint (policy should be strict).
// ============================================================================

v1.MapPost("/security/revoke-token", async (
    string jti,
    ITokenRevocationStore store,
    IOptions<TokenHardeningOptions> opt,
    CancellationToken ct) =>
{
    // Revoke for the max age window (+ safety buffer).
    var ttl = TimeSpan.FromMinutes(opt.Value.MaxAccessTokenAgeMinutes + 5);

    await store.RevokeAsync(jti, ttl, ct);

    return Results.Ok(new { revoked = true, jti, ttlMinutes = ttl.TotalMinutes });
})
.RequireAuthorization(AuthzPolicies.ReportsReadPolicyName) // Prefer an Admin/Security policy in production.
.WithOpenApi();

#endregion

#region Endpoints (V2/V3/V4) — Kept Minimal in this cleaned version

// NOTE:
// Your original code contains multiple variants of raw-record endpoints (v2, v3, v4).
// In a production codebase, consider extracting these into dedicated extension methods:
// - app.MapRawRecordsV2(v2);
// - app.MapRawRecordsV3(v3);
// - app.MapRawRecordsV4(v4);
// to keep Program.cs smaller and more maintainable.

#endregion

#region Response Headers — Tenant Reflection (Optional)

// Optional: Reflect tenant id as a response header for proxy/cache keys.
// IMPORTANT: Only do this if your reverse proxy config is designed to use it.
app.Use(async (ctx, next) =>
{
    ctx.Response.OnStarting(() =>
    {
        var tid = ctx.User.FindFirstValue("tid");
        if (!string.IsNullOrWhiteSpace(tid))
            ctx.Response.Headers["X-Tenant-Id"] = tid;

        return Task.CompletedTask;
    });

    await next();
});

#endregion

#region Run

app.Run();

#endregion

#region Local Helpers

/// <summary>
/// Cache key builder for raw endpoints (tenant + query + cursor).
/// NOTE: In production, avoid embedding raw filter values if they can include sensitive content.
/// Prefer hashing filter expressions.
/// </summary>
static string RawCacheKey(string tenantId, RawQuery q, int take)
{
    return $"raw:v1:tenant:{tenantId}:limit:{take}:filter:{q.Filter ?? ""}:cursor:{q.NextPageToken ?? ""}";
}

#endregion

#region Request Models (API Contracts)

// These records represent API request/response shapes.
// Keep them in a separate file in production (e.g., Contracts/ folder) to keep Program.cs small.

public sealed record CallRecordsListQuery(
    int? Limit,
    string? Offset,   // signed cursor token
    string? SortAsc,
    string? SortDesc);

public sealed record FieldFilter(
    string Field,
    FilterOp Op,
    string[] Values);

public sealed record CallRecordsCursor(
    string TenantId,
    string FilterHash,
    string Sort,
    string LastKey,
    DateTimeOffset IssuedUtc);

public sealed record PageCursor(
    string TenantId,
    string? FilterHash,
    string Sort,
    string LastKey,
    DateTimeOffset IssuedUtc);

public sealed record CreateOrderRequest(string ProductId, int Quantity);

/// <summary>
/// Raw query contract for list endpoints.
/// </summary>
public record RawQuery(string? Filter, int? Limit, string? NextPageToken);

/// <summary>
/// Search query contract for search endpoints.
/// </summary>
public sealed record SearchQuery(
    string? Query,
    string[]? Channels,
    DateTimeOffset? FromUtc,
    DateTimeOffset? ToUtc,
    int? Limit,
    string? NextPageToken);

public enum JobState { Queued, Running, Succeeded, Failed, Canceled }

public sealed record JobInfo(
    string JobId,
    string TenantId,
    string Kind,
    JobState State,
    DateTimeOffset CreatedUtc,
    DateTimeOffset? StartedUtc,
    DateTimeOffset? CompletedUtc,
    string? ResultLocation,
    string? Error);

public sealed record StartExportRequest(string? Filter, int? Limit, string? NextPageToken);
public sealed record StartJobResponse(string JobId, string StatusUrl, string? ResultUrl);

#endregion
