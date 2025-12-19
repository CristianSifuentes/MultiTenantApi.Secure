using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Threading.RateLimiting;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.HttpOverrides;
using Microsoft.AspNetCore.RateLimiting;
using Microsoft.IdentityModel.Logging;
using Microsoft.IdentityModel.Tokens;
using Microsoft.OpenApi.Models;
using Mapster;
using MapsterMapper;
using Serilog;
using MultiTenantApi.Common;
using MultiTenantApi.Mapping;
using MultiTenantApi.Middleware;
using MultiTenantApi.Models;
using MultiTenantApi.Security;
using MultiTenantApi.Services;

var builder = WebApplication.CreateBuilder(args);

// =====================================================
// Logging (structured) — avoids leaking secrets in logs
// =====================================================
Log.Logger = new LoggerConfiguration()
    .ReadFrom.Configuration(builder.Configuration)
    .Enrich.FromLogContext()
    .WriteTo.Console()
    .CreateLogger();

builder.Host.UseSerilog();

// Disable legacy claim type mapping so you see tid/scp/roles as-is.
JwtSecurityTokenHandler.DefaultMapInboundClaims = false;

// =====================================================
// Config (Multi-tenant)
// =====================================================
var azureAd = builder.Configuration.GetSection("AzureAd");
var instance = azureAd["Instance"] ?? "https://login.microsoftonline.com/";
var tenantId = azureAd["TenantId"] ?? "common";
var authority = $"{instance.TrimEnd('/')}/{tenantId}/v2.0";

var audience = azureAd["Audience"]
    ?? throw new InvalidOperationException("AzureAd:Audience is required (e.g., api://{API_CLIENT_ID}).");

builder.Services.Configure<SyntheticIdOptions>(builder.Configuration.GetSection("SyntheticId"));
builder.Services.Configure<RateLimitOptions>(builder.Configuration.GetSection("RateLimiting"));

// =====================================================
// AuthN (JWT Bearer) — hardened issuer + audience checks
// =====================================================
builder.Services
    .AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
    .AddJwtBearer(options =>
    {
        options.Authority = authority;

        // IMPORTANT: We validate audience explicitly to prevent tokens meant for other APIs being accepted.
        options.TokenValidationParameters = new TokenValidationParameters
        {
            ValidateAudience = true,
            ValidAudiences = new[]
            {
                audience,              // api://{clientId}
                azureAd["ClientId"]    // {clientId} (GUID) — helps tooling like Postman
            }.Where(x => !string.IsNullOrWhiteSpace(x)).ToArray(),

            ValidateIssuer = true,
            IssuerValidator = TenantAllowListIssuerValidator.Build(builder.Configuration),

            NameClaimType = "name",
            RoleClaimType = "roles",
        };

        // Never persist tokens server-side.
        options.SaveToken = false;

        IdentityModelEventSource.ShowPII = builder.Environment.IsDevelopment();

        options.Events = new JwtBearerEvents
        {
            OnAuthenticationFailed = ctx =>
            {
                // DO NOT log raw tokens. Log correlation info only.
                ctx.HttpContext.Items["auth_failed"] = true;
                return Task.CompletedTask;
            }
        };
    });

// =====================================================
// AuthZ (policies) — supports delegated scopes + app roles
// =====================================================
builder.Services.AddAuthorization(options =>
{
    AuthzPolicies.Configure(options, builder.Configuration);

    options.AddPolicy("AdminOnly", p =>
    {
        p.RequireAuthenticatedUser();
        p.RequireRole("Admin");
    });
});

// =====================================================
// Rate limiting — partition by identity (oid/appid) with IP fallback
// mitigates: brute force, scraping, DoS logical (OWASP API4)
// =====================================================
//builder.Services.AddRateLimiter(o =>
//{
//    o.RejectionStatusCode = StatusCodes.Status429TooManyRequests;

//    o.GlobalLimiter = PartitionedRateLimiter.Create<HttpContext, string>(ctx =>
//    {
//        // Prefer stable identity keys
//        var user = ctx.User;
//        var key =
//            user.FindFirstValue("oid") ??
//            user.FindFirstValue("appid") ??
//            user.FindFirstValue("azp") ??
//            ctx.Connection.RemoteIpAddress?.ToString() ??
//            "anonymous";

//        var limits = ctx.RequestServices.GetRequiredService<Microsoft.Extensions.Options.IOptions<RateLimitOptions>>().Value;

//        // Two-level limiter: burst + sustained
//        return RateLimitPartition.GetChainedLimiter(key,
//            _ => new[]
//            {
//                RateLimitPartition.GetFixedWindowLimiter(
//                    partitionKey: key + ":burst",
//                    factory: _ => new FixedWindowRateLimiterOptions
//                    {
//                        PermitLimit = Math.Max(1, limits.BurstPer10Seconds),
//                        Window = TimeSpan.FromSeconds(10),
//                        QueueLimit = 0,
//                        AutoReplenishment = true
//                    }),
//                RateLimitPartition.GetFixedWindowLimiter(
//                    partitionKey: key + ":sustained",
//                    factory: _ => new FixedWindowRateLimiterOptions
//                    {
//                        PermitLimit = Math.Max(1, limits.PerIdentityPerMinute),
//                        Window = TimeSpan.FromMinutes(1),
//                        QueueLimit = 0,
//                        AutoReplenishment = true
//                    })
//            });
//    });

//    // Optional: endpoint-specific limiter (stricter for exports)
//    o.AddFixedWindowLimiter("exports", opt =>
//    {
//        opt.PermitLimit = 60;
//        opt.Window = TimeSpan.FromMinutes(1);
//        opt.QueueLimit = 0;
//        opt.AutoReplenishment = true;
//    });
//});
builder.Services.AddRateLimiter(o =>
{
    o.RejectionStatusCode = StatusCodes.Status429TooManyRequests;

    o.GlobalLimiter = PartitionedRateLimiter.Create<HttpContext, string>(ctx =>
    {
        var user = ctx.User;

        var key =
            user.FindFirstValue("oid") ??
            user.FindFirstValue("appid") ??
            user.FindFirstValue("azp") ??
            ctx.Connection.RemoteIpAddress?.ToString() ??
            "anonymous";

        var limits = ctx.RequestServices
            .GetRequiredService<Microsoft.Extensions.Options.IOptions<RateLimitOptions>>()
            .Value;

        // TokenBucket = burst + sustained en un solo limiter (sin chaining)
        // - TokenLimit: tamaño del burst
        // - TokensPerPeriod/ReplenishmentPeriod: ritmo sostenido
        return RateLimitPartition.GetTokenBucketLimiter(
            partitionKey: key,
            factory: _ => new TokenBucketRateLimiterOptions
            {
                TokenLimit = Math.Max(1, limits.BurstPer10Seconds),
                QueueLimit = 0,
                QueueProcessingOrder = QueueProcessingOrder.OldestFirst,

                // Sostenido por minuto:
                TokensPerPeriod = Math.Max(1, limits.PerIdentityPerMinute),
                ReplenishmentPeriod = TimeSpan.FromMinutes(1),
                AutoReplenishment = true
            });
    });

    // Endpoint-specific limiter (exports) - lo puedes dejar igual
    o.AddFixedWindowLimiter("exports", opt =>
    {
        opt.PermitLimit = 60;
        opt.Window = TimeSpan.FromMinutes(1);
        opt.QueueLimit = 0;
        opt.AutoReplenishment = true;
    });
});

// =====================================================
// Swagger (OpenAPI) — bearer auth
// =====================================================
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen(o =>
{
    o.SwaggerDoc("v1", new() { Title = "MultiTenantApi.Secure", Version = "v1" });

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
                Reference = new OpenApiReference { Type = ReferenceType.SecurityScheme, Id = "bearerAuth" }
            },
            Array.Empty<string>()
        }
    });
});

// =====================================================
// Mapster + Services (exports)
// =====================================================
MapsterConfig.RegisterMaps();
builder.Services.AddSingleton(TypeAdapterConfig.GlobalSettings);
builder.Services.AddSingleton<IMapper, ServiceMapper>();

builder.Services.AddSingleton<ISyntheticIdService, SyntheticIdService>();
builder.Services.AddSingleton<IRawDataService, InMemoryRawDataService>();
builder.Services.AddSingleton<ICallRecordService, InMemoryCallRecordService>();

// =====================================================
// Pipeline hardening
// =====================================================
var app = builder.Build();

// Behind reverse proxies (Azure, Nginx, APIM): trust forwarded headers
app.UseForwardedHeaders(new ForwardedHeadersOptions
{
    ForwardedHeaders = ForwardedHeaders.XForwardedFor | ForwardedHeaders.XForwardedProto,
    // In real deployment, set KnownProxies/KnownNetworks
});

// Uniform error responses + no stack trace leaks
app.UseExceptionHandler("/error");

// Enforce HTTPS at the edge and inside app (defense-in-depth)
app.UseHsts();
app.UseMiddleware<EnforceHttpsMiddleware>();

// Security headers (clickjacking, MIME sniffing, etc.)
app.UseMiddleware<SecurityHeadersMiddleware>();

// Correlation ID for audit + tracing
app.UseMiddleware<CorrelationIdMiddleware>();

// Audit logging (request -> response) without leaking tokens/PII
app.UseMiddleware<AuditMiddleware>();

app.UseSwagger();
app.UseSwaggerUI(c =>
{
    c.SwaggerEndpoint("/swagger/v1/swagger.json", "MultiTenantApi.Secure v1");
});

app.UseRateLimiter();
app.UseAuthentication();
app.UseAuthorization();

// =====================================================
// Error endpoint (ProblemDetails)
// =====================================================
app.MapGet("/error", (HttpContext ctx) =>
{
    // RFC7807 ProblemDetails
    var traceId = ctx.TraceIdentifier;
    return Results.Problem(
        title: "An unexpected error occurred.",
        statusCode: StatusCodes.Status500InternalServerError,
        extensions: new Dictionary<string, object?> { ["traceId"] = traceId });
}).ExcludeFromDescription();

// =====================================================
// Health / diagnostics
// =====================================================
app.MapGet("/health", () => Results.Ok(new { status = "ok", utc = DateTimeOffset.UtcNow }))
   .AllowAnonymous()
   .WithOpenApi();

app.MapGet("/whoami", (ClaimsPrincipal user) =>
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

// =====================================================
// Secure sample endpoints
// =====================================================
app.MapGet("/documents", (ClaimsPrincipal user) =>
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

app.MapGet("/reports", (ClaimsPrincipal user) =>
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

// =====================================================
// RAW data export — hardened: rate limiting + safe field projection + synthetic IDs
// =====================================================
app.MapGet("/v1/raw-data", async (
    HttpContext http,
    [AsParameters] RawQuery q,
    IRawDataService dataSvc,
    ISyntheticIdService synth) =>
{
    // clamp limit to prevent resource abuse
    var take = Math.Clamp(q.Limit ?? 100, 1, 100);

    var page = await dataSvc.QueryAsync(q.Filter, q.NextPageToken, take, http.RequestAborted);

    var items = page.Items.Select(r =>
    {
        // Project safe fields only + apply masking if configured on attributes
        var shape = FieldProjector.ToApiShape(r, synth);

        // Provide a synthetic stable id for external correlation, without revealing internal IDs.
        shape["syntheticId"] = synth.Create("raw", r.InternalId.ToString("N"));
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
.RequireRateLimiting("exports")
.RequireAuthorization(AuthzPolicies.DocumentsReadPolicyName)
.Produces(StatusCodes.Status200OK)
.ProducesProblem(StatusCodes.Status401Unauthorized)
.ProducesProblem(StatusCodes.Status403Forbidden)
.ProducesProblem(StatusCodes.Status429TooManyRequests)
.WithOpenApi();

// =====================================================
// Metadata export — inventory of exposed fields (OWASP API9)
// =====================================================
app.MapGet("/v1/export/metadata/call-records", async (
    ICallRecordService svc,
    IMapper mapper,
    CancellationToken ct) =>
{
    var fields = ApiMetadataBuilder.BuildFor<CallRecord>();

    // Sample: always map to safe DTO (masking + synthetic ids)
    var sampleDomain = await svc.GetSampleAsync(ct);
    var sampleExport = mapper.Map<List<CallRecordExportDto>>(sampleDomain);

    var response = new EntityMetadataResponse<CallRecordExportDto>(
        EntityName: "CallRecord",
        Version: "v1",
        Fields: fields,
        Sample: sampleExport);

    return Results.Ok(response);
})
.RequireRateLimiting("exports")
.RequireAuthorization(AuthzPolicies.ReportsReadPolicyName)
.Produces<EntityMetadataResponse<CallRecordExportDto>>(StatusCodes.Status200OK)
.ProducesProblem(StatusCodes.Status401Unauthorized)
.ProducesProblem(StatusCodes.Status403Forbidden)
.ProducesProblem(StatusCodes.Status429TooManyRequests)
.WithOpenApi();

// =====================================================
// Call records export — safe DTO only
// =====================================================
app.MapGet("/v1/export/call-records", async (
    ICallRecordService svc,
    IMapper mapper,
    ISyntheticIdService synth,
    CancellationToken ct) =>
{
    var records = await svc.GetSampleAsync(ct);
    var dto = mapper.Map<List<CallRecordExportDto>>(records);
    for (var i = 0; i < dto.Count; i++)
    {
        var src = records[i];
        dto[i] = dto[i] with { SyntheticCallId = synth.Create("call", src.CallId, src.InteractionId.ToString()) };
    }

    return Results.Ok(new
    {
        items = dto,
        count = dto.Count
    });
})
.RequireRateLimiting("exports")
.RequireAuthorization(AuthzPolicies.ReportsReadPolicyName)
.WithOpenApi();

app.Run();

public record RawQuery(string? Filter, int? Limit, string? NextPageToken);
