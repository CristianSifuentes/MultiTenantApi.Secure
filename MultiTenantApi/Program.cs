using Mapster;
using MapsterMapper;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.HttpOverrides;
using Microsoft.AspNetCore.RateLimiting;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Logging;
using Microsoft.IdentityModel.Tokens;
using Microsoft.OpenApi.Models;
using MultiTenantApi.Common;
using MultiTenantApi.Infrastructure; // JsonWebToken (faster parser)
using MultiTenantApi.Mapping;
using MultiTenantApi.Middleware;
using MultiTenantApi.Models;
using MultiTenantApi.Security;
using MultiTenantApi.Security.IdempotencyStore;
using MultiTenantApi.Services;
using MultiTenantApi.Services.HMAC;
using Serilog;
using System;
using System.ComponentModel;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Threading.RateLimiting;
using static System.Net.WebRequestMethods;

var builder = WebApplication.CreateBuilder(args);

// =====================================================
// Logging (structured) — avoids leaking secrets in logs
// =====================================================
Log.Logger = new LoggerConfiguration()
    .ReadFrom.Configuration(builder.Configuration)
    .Enrich.FromLogContext()
    // 🔥 evita que logs “accidentalmente” lleven headers peligrosos
    .Enrich.With(new RedactSensitiveHeadersEnricher(
        new HttpContextAccessor())) // en prod, mejor resolverlo desde DI (ver nota abajo)
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

////existe ya una forma donde se hace una inyección de dependencias de 
//// una sección de en el appsetting de nombre "RateLimiting"
////"RateLimiting": {
////    "PerIdentityPerMinute": 300,
////    "BurstPer10Seconds": 50
////  }, analizar ver el tema de las opciones avanzadas, comente el servicio y el appsetting
//builder.Services.Configure<RateLimitOptions>(builder.Configuration.GetSection("RateLimiting"));
builder.Services.Configure<RateLimitingEnterpriseOptions>(
    builder.Configuration.GetSection("RateLimitingEnterprise"));

// Esto NO reemplaza WAF, pero hace tu app resistente incluso si el WAF falla o está mal configurado. 
builder.Services.Configure<RequestLimitsOptions>(builder.Configuration.GetSection("RequestLimits"));



builder.Services.AddDistributedMemoryCache(); // dev


builder.Services.Configure<TokenHardeningOptions>(
    builder.Configuration.GetSection("TokenHardening"));

// =====================================================
// AuthN (JWT Bearer) — hardened issuer + audience checks
// =====================================================
builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
.AddJwtBearer(options =>
{
    options.Authority = authority;
    options.RequireHttpsMetadata = true;

    var hardening = builder.Configuration.GetSection("TokenHardening").Get<TokenHardeningOptions>() ?? new();

    options.TokenValidationParameters = new TokenValidationParameters
    {
        // ✅ Strong signature required
        RequireSignedTokens = true,
        ValidateIssuerSigningKey = true,
        RequireExpirationTime = true,

        // ✅ Strict iss / aud (you already do this)
        ValidateIssuer = true,
        IssuerValidator = TenantAllowListIssuerValidator.Build(builder.Configuration),

        ValidateAudience = true,
        ValidAudiences = new[]
        {
            audience,
            azureAd["ClientId"]
        }.Where(x => !string.IsNullOrWhiteSpace(x)).ToArray(),

        // ✅ exp / nbf strict with controlled skew
        ValidateLifetime = true,
        ClockSkew = TimeSpan.FromSeconds(Math.Clamp(hardening.ClockSkewSeconds, 0, 120)),

        // ✅ Algorithm whitelist (RS256/ES256)
        // For Entra you can restrict to RS256 only if you want maximum strictness.
        ValidAlgorithms = new[]
        {
            SecurityAlgorithms.RsaSha256, // RS256
            SecurityAlgorithms.EcdsaSha256 // ES256
        },

        NameClaimType = "name",
        RoleClaimType = "roles",
    };

    // ✅ Key rollover safe (kid changes)
    options.RefreshOnIssuerKeyNotFound = true;

    // (bien: no persistes tokens)
    options.SaveToken = false;

    options.Events = new JwtBearerEvents
    {
        OnTokenValidated = async ctx =>
        {
            // Hard block "alg":"none" and any non-whitelisted alg (defense-in-depth)
            if (ctx.SecurityToken is JwtSecurityToken jwt)
            {
                var alg = jwt.Header.Alg;

                if (string.Equals(alg, "none", StringComparison.OrdinalIgnoreCase))
                {
                    ctx.Fail("Rejected unsigned JWT (alg=none).");
                    return;
                }

                // Whitelist check (defense-in-depth)
                if (alg is null ||
                    !(alg.Equals("RS256", StringComparison.OrdinalIgnoreCase) ||
                      alg.Equals("ES256", StringComparison.OrdinalIgnoreCase)))
                {
                    ctx.Fail($"Rejected JWT with unsupported alg='{alg}'.");
                    return;
                }
            }

            // Optional: add anti-replay / revocation checks here (next section)
            var revocation = ctx.HttpContext.RequestServices.GetRequiredService<ITokenRevocationStore>();
            var hard = ctx.HttpContext.RequestServices.GetRequiredService<IOptions<TokenHardeningOptions>>().Value;

            if (hard.EnableJtiReplayProtection)
            {
                var jti = ctx.Principal?.FindFirstValue(System.IdentityModel.Tokens.Jwt.JwtRegisteredClaimNames.Jti);
                if (string.IsNullOrWhiteSpace(jti))
                {
                    // You can choose to require jti strictly, but Entra doesn't always include it in access tokens.
                    // If you want strict mode: ctx.Fail("Missing jti."); return;
                }
                else
                {
                    // 1) If token revoked -> block
                    if (await revocation.IsRevokedAsync(jti, ctx.HttpContext.RequestAborted))
                    {
                        ctx.Fail("Token has been revoked.");
                        return;
                    }

                    // 2) Replay protection: same jti seen again -> block (optional strict)
                    // If you don't want strict replay block (e.g. same token reused legitimately), disable this.
                    var replayOk = await revocation.TryMarkSeenAsync(jti, TimeSpan.FromMinutes(hard.JtiCacheMinutes), ctx.HttpContext.RequestAborted);
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

    // Delegate admin only direct policy
    options.AddPolicy("AdminOnly", p =>
    {
        p.RequireAuthenticatedUser();
        p.RequireRole("Admin");
    });
});



builder.Services.AddRateLimiter(o =>
{


    //La idea: para exports/ search aplicas tres limiters en paralelo(tenant + client + user).
    //¿Que es GetChainedLimiter?
    o.RejectionStatusCode = StatusCodes.Status429TooManyRequests;

    // 1) GLOBAL: user/client/ip (general anti-abuse)
    o.GlobalLimiter = PartitionedRateLimiter.Create<HttpContext, string>(ctx =>
    {
        var key =
            RateLimitKeyFactory.GetUserKey(ctx) != "user:anonymous"
                ? RateLimitKeyFactory.GetUserKey(ctx)
                : RateLimitKeyFactory.GetClientKey(ctx) != "client:anonymous"
                    ? RateLimitKeyFactory.GetClientKey(ctx)
                    : RateLimitKeyFactory.GetIpFallback(ctx);

        // Usa tus RateLimitOptions actuales aquí
        var limits = ctx.RequestServices.GetRequiredService<IOptions<RateLimitOptions>>().Value;

        return RateLimitPartition.GetTokenBucketLimiter(
            partitionKey: key,
            factory: _ => new TokenBucketRateLimiterOptions
            {
                TokenLimit = Math.Max(1, limits.BurstPer10Seconds),
                TokensPerPeriod = Math.Max(1, limits.PerIdentityPerMinute),
                ReplenishmentPeriod = TimeSpan.FromMinutes(1),
                QueueLimit = 0,
                QueueProcessingOrder = QueueProcessingOrder.OldestFirst,
                AutoReplenishment = true
            });
    });

    // 2) ENDPOINT POLICIES: tenant fairness
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

    // 3) LOGIN: per-IP + per-client (anti credential stuffing)
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

    //6) “Impresionante” nivel enterprise: rate limit por client_id explícito en policies
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

    // Cómo lo usas(esto es lo importante)
    // Exports:
    //  .RequireRateLimiting("exports-tenant")
    //  y además GlobalLimiter ya aplica por user / client / ip automáticamente.
    // Search:
    //  .RequireRateLimiting("search-tenant")
    // Login endpoints:
    //  .RequireRateLimiting("login")

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
//        var user = ctx.User;

//        var key =
//            user.FindFirstValue("oid") ??
//            user.FindFirstValue("appid") ??
//            user.FindFirstValue("azp") ??
//            ctx.Connection.RemoteIpAddress?.ToString() ??
//            "anonymous";

//        var limits = ctx.RequestServices
//            .GetRequiredService<Microsoft.Extensions.Options.IOptions<RateLimitOptions>>()
//            .Value;

//        // TokenBucket = burst + sustained en un solo limiter (sin chaining)
//        // - TokenLimit: tamaño del burst
//        // - TokensPerPeriod/ReplenishmentPeriod: ritmo sostenido
//        return RateLimitPartition.GetTokenBucketLimiter(
//            partitionKey: key,
//            factory: _ => new TokenBucketRateLimiterOptions
//            {
//                TokenLimit = Math.Max(1, limits.BurstPer10Seconds),
//                QueueLimit = 0,
//                QueueProcessingOrder = QueueProcessingOrder.OldestFirst,

//                // Sostenido por minuto:
//                TokensPerPeriod = Math.Max(1, limits.PerIdentityPerMinute),
//                ReplenishmentPeriod = TimeSpan.FromMinutes(1),
//                AutoReplenishment = true
//            });
//    });

//    // Endpoint-specific limiter (exports) - lo puedes dejar igual
//    o.AddFixedWindowLimiter("exports", opt =>
//    {
//        opt.PermitLimit = 60;
//        opt.Window = TimeSpan.FromMinutes(1);
//        opt.QueueLimit = 0;
//        opt.AutoReplenishment = true;
//    });
//});

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


#region DependencyInjection (DI) 
builder.Services.AddSingleton(TypeAdapterConfig.GlobalSettings);
builder.Services.AddSingleton<IMapper, ServiceMapper>();
builder.Services.AddSingleton<ISyntheticIdService, SyntheticIdService>();
builder.Services.AddSingleton<IRawDataService, InMemoryRawDataService>();
builder.Services.AddSingleton<ICallRecordService, InMemoryCallRecordService>();
builder.Services.AddSingleton<TokenAgeGuardMiddleware>();
builder.Services.AddSingleton<BlockApiKeyOnSensitiveRoutesMiddleware>();
builder.Services.AddSingleton<ITokenRevocationStore, DistributedTokenRevocationStore>();
//Esto NO reemplaza WAF, pero hace tu app resistente incluso si el WAF falla o está mal configurado.
builder.Services.AddSingleton<RequestLimitsMiddleware>();
// WafSignalsMiddleware (detección + scoring + logging + “bot hints”)
builder.Services.AddSingleton<WafSignalsMiddleware>();
// 1) “Nunca secrets en URLs” — dónde se implementa y cómo
builder.Services.AddSingleton<DenySecretsInUrlMiddleware>();
//3) No meter secretos en querystring (se loguea en proxies)
builder.Services.AddSingleton<BlockSensitiveQueryStringMiddleware>();
//5.3 Middleware Idempotency(solo para POST/PUT/PATCH)
builder.Services.AddSingleton<IIdempotencyStore, DistributedIdempotencyStore>();
builder.Services.AddSingleton<IdempotencyMiddleware>();

//4) Implementación enterprise: Cursor firmado + contrato estándar
builder.Services.AddSingleton<ICursorProtector, HmacCursorProtector>();


#endregion




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

#region Middleware
app.UseMiddleware<EnforceHttpsMiddleware>();

// Security headers (clickjacking, MIME sniffing, etc.)
// Necesitamos ver de donde salio?? y que hace??
app.UseMiddleware<SecurityHeadersMiddleware>();

// Correlation ID for audit + tracing
app.UseMiddleware<CorrelationIdMiddleware>();

// Audit logging (request -> response) without leaking tokens/PII
app.UseMiddleware<AuditMiddleware>();

// 5) Evitar “DIY auth” (API keys sin controles) en datos sensibles
app.UseMiddleware<BlockApiKeyOnSensitiveRoutesMiddleware>();

//Esto NO reemplaza WAF, pero hace tu app resistente incluso si el WAF falla o está mal configurado.
app.UseMiddleware<RequestLimitsMiddleware>();

//4.2 WafSignalsMiddleware (detección + scoring + logging + “bot hints”)
app.UseMiddleware<WafSignalsMiddleware>();

// 1) “Nunca secrets en URLs” — dónde se implementa y cómo
app.UseMiddleware<DenySecretsInUrlMiddleware>();


// 3) No meter secretos en querystring (se loguea en proxies)
app.UseMiddleware<BlockSensitiveQueryStringMiddleware>();

//5.3 Middleware Idempotency(solo para POST/PUT/PATCH)
app.UseMiddleware<IdempotencyMiddleware>();

#endregion


app.UseSwagger();
app.UseSwaggerUI(c =>
{
    c.SwaggerEndpoint("/swagger/v1/swagger.json", "MultiTenantApi.Secure v1");
});

app.UseRateLimiter();
app.UseAuthentication();
// recommended: AFTER UseAuthentication so ctx.User is populated.
app.UseMiddleware<TokenAgeGuardMiddleware>();
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

app.MapGet("api/v1/whoami", (ClaimsPrincipal user) =>
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
app.MapGet("api/v1/documents", (ClaimsPrincipal user) =>
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

app.MapGet("api/v1/reports", (ClaimsPrincipal user) =>
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
app.MapGet("api/v1/raw-records", async (
    HttpContext http,
    [AsParameters] RawQuery q,
    IRawDataService dataSvc,
    ISyntheticIdService synth,
    ClaimsPrincipal user) =>
{
    var tenant = TenantContextFactory.From(user);

    // clamp limit to prevent resource abuse
    // Quien implemente take usa limit cursor
    // necesito volver a ver como fundiona el limit cursor
    var take = Math.Clamp(q.Limit ?? 100, 1, 100);

    //before
    //var page = await dataSvc.QueryAsync(q.Filter, q.NextPageToken, take, http.RequestAborted);

    // after
    var page = await dataSvc.QueryAsync(tenant.TenantId, q.Filter, q.NextPageToken, take, http.RequestAborted);


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
.RequireRateLimiting("exports-tenant")
.RequireAuthorization(AuthzPolicies.DocumentsReadPolicyName)
.Produces(StatusCodes.Status200OK)
.ProducesProblem(StatusCodes.Status401Unauthorized)
.ProducesProblem(StatusCodes.Status403Forbidden)
.ProducesProblem(StatusCodes.Status429TooManyRequests)
.WithOpenApi();

// =====================================================
// Metadata export — inve
//
// ntory of exposed fields (OWASP API9)
// =====================================================
app.MapGet("api/v1/export/metadata/call-records", async (
    ICallRecordService svc,
    IMapper mapper,
    CancellationToken ct,
    ClaimsPrincipal user
    ) =>
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
.RequireRateLimiting("exports-tenant")
.RequireAuthorization(AuthzPolicies.ReportsReadPolicyName)
.Produces<EntityMetadataResponse<CallRecordExportDto>>(StatusCodes.Status200OK)
.ProducesProblem(StatusCodes.Status401Unauthorized)
.ProducesProblem(StatusCodes.Status403Forbidden)
.ProducesProblem(StatusCodes.Status429TooManyRequests)
.WithOpenApi();

// =====================================================
// Call records export — safe DTO only
// =====================================================
app.MapGet("api/v1/export/call-records", async (
    ICallRecordService svc,
    IMapper mapper,
    ISyntheticIdService synth,
    CancellationToken ct,
    ClaimsPrincipal user) =>
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
.RequireRateLimiting("exports-tenant")
.RequireAuthorization(AuthzPolicies.ReportsReadPolicyName)
.WithOpenApi();



//En tu caso con Entra, “login” vive fuera, pero aplica perfecto a:
/// password - reset / request
/// send - otp
/// invite
/// onboarding / start
//(flujos sensibles OWASP API6)


// =====================================================
// SEARCH — hardened: ABAC tenant scope + strict validation + cursor pagination
// Threats: OWASP API4 (resource consumption), API1 (BOLA via cross-tenant), scraping/fuzzing
// =====================================================
app.MapGet("api/v1/search", async (
    HttpContext http,
    [AsParameters] SearchQuery q,
    ClaimsPrincipal user,
    IRawDataService dataSvc,
    ISyntheticIdService synth) =>
{
    // ✅ ABAC: tenant scoping (deny-by-default)
    var tenant = TenantContextFactory.From(user);
    if (string.IsNullOrWhiteSpace(tenant.TenantId))
        return Results.Forbid();

    // ✅ Validate BEFORE touching data layer (cheap rejection)
    var v = SearchQueryValidator.Validate(q);
    if (!v.ok)
    {
        // consistent error shape (do not leak details)
        return Results.BadRequest(new
        {
            error = "invalid_query",
            message = v.error
        });
    }

    // ✅ Hard clamp (defense-in-depth)
    // Quien implemente take usa limit cursor
    var take = Math.Clamp(q.Limit ?? 25, 1, 100);

    // ✅ ABAC enforcement at the data layer: pass tenantId
    var page = await dataSvc.SearchAsync(
        tenantId: tenant.TenantId,
        query: q.Query!,
        channels: q.Channels,
        fromUtc: q.FromUtc,
        toUtc: q.ToUtc,
        nextToken: q.NextPageToken,
        take: take,
        ct: http.RequestAborted);

    // ✅ Deny-by-default projection (never return domain raw object directly)
    // Only return "safe" fields + synthetic stable id
    var items = page.Items.Select(r =>
    {
        var shape = new Dictionary<string, object?>
        {
            ["syntheticId"] = synth.Create("raw", r.InternalId.ToString("N")),
            ["createdAt"] = r.CreatedAt,
            ["channel"] = r.Channel,
            ["textPreview"] = SearchQueryValidator.SafePreview(r.Text, maxLen: 160)
        };

        // Optionally: expose a stable synthetic user id (avoid leaking real internal user ids)
        shape["syntheticUserId"] = string.IsNullOrWhiteSpace(r.UserInternalId)
            ? null
            : synth.Create("user", r.UserInternalId);

        return shape;
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
.RequireAuthorization(AuthzPolicies.ReportsReadPolicyName) // or create a Search policy
.Produces(StatusCodes.Status200OK)
.ProducesProblem(StatusCodes.Status401Unauthorized)
.ProducesProblem(StatusCodes.Status403Forbidden)
.ProducesProblem(StatusCodes.Status429TooManyRequests)
.WithOpenApi();


app.MapGet("api/v1/call-records", async (
    ICallRecordService svc,
    IMapper mapper,
    ISyntheticIdService synth,
    CancellationToken ct,
    ClaimsPrincipal user) =>
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
.RequireRateLimiting("exports-tenant")
.RequireAuthorization(AuthzPolicies.ReportsReadPolicyName)
.WithOpenApi();


app.MapGet("api/v2/raw-records", async (
    HttpContext http,
    [AsParameters] RawQuery q,
    IRawDataService dataSvc,
    ISyntheticIdService synth,
    ClaimsPrincipal user) =>
{
    // ABAC
    var tenant = TenantContextFactory.From(user);

    // clamp limit to prevent resource abuse
    var take = Math.Clamp(q.Limit ?? 100, 1, 100);

    //before
    //var page = await dataSvc.QueryAsync(tenant.TenantId, q.Filter, q.NextPageToken, take, ct);

    // after
    var page = await dataSvc.QueryAsync(tenant.TenantId, q.Filter, q.NextPageToken, take, http.RequestAborted);


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
.RequireRateLimiting("exports-tenant")
.RequireAuthorization(AuthzPolicies.ReportsReadPolicyName)
.Produces(StatusCodes.Status200OK)
.ProducesProblem(StatusCodes.Status401Unauthorized)
.ProducesProblem(StatusCodes.Status403Forbidden)
.ProducesProblem(StatusCodes.Status429TooManyRequests)
.WithOpenApi();

app.MapGet("api/v3/raw-records", async (
    HttpContext http,
    [AsParameters] RawQuery q,
    IRawDataService dataSvc,
    ISyntheticIdService synth,
    ICursorProtector cursorProtector,
    ClaimsPrincipal user) =>
{
    var tenant = TenantContextFactory.From(user);
    if (string.IsNullOrWhiteSpace(tenant.TenantId))
        return Results.Forbid();

    var take = Math.Clamp(q.Limit ?? 100, 1, 100);

    // ✅ Early rejection (cheap)
    var v = RawQueryValidator.Validate(q.Filter, q.NextPageToken, take);
    if (!v.ok)
        return Results.BadRequest(new { error = "invalid_query", message = v.error });

    // ✅ Unprotect cursor (if present)
    PageCursor? cursor = null;
    if (!string.IsNullOrWhiteSpace(q.NextPageToken))
    {
        if (!cursorProtector.TryUnprotect(q.NextPageToken!, out var c))
            return Results.BadRequest(new { error = "invalid_cursor" });

        // ✅ Bind to tenant
        if (!string.Equals(c.TenantId, tenant.TenantId, StringComparison.Ordinal))
            return Results.BadRequest(new { error = "cursor_tenant_mismatch" });

        // ✅ Bind to filter
        var expectedFilterHash = FilterHasher.Hash(q.Filter);
        if (!string.Equals(c.FilterHash, expectedFilterHash, StringComparison.Ordinal))
            return Results.BadRequest(new { error = "cursor_filter_mismatch" });

        // ✅ Optional TTL
        if (c.IssuedUtc < DateTimeOffset.UtcNow.AddMinutes(-30))
            return Results.BadRequest(new { error = "cursor_expired" });

        cursor = c;
    }

    // ✅ Ask data layer with cursor.LastKey (not raw token)
    // Recomendación: cambia tu IRawDataService para aceptar "lastKey" en vez de token opaco.
    var page = await dataSvc.QueryAsync(
        tenant.TenantId,
        q.Filter,
        nextToken: cursor?.LastKey, // aquí
        take,
        http.RequestAborted);

    var items = page.Items.Select(r =>
    {
        var shape = FieldProjector.ToApiShape(r, synth);
        shape["syntheticId"] = synth.Create("raw", r.InternalId.ToString("N"));
        return shape;
    });

    // ✅ Produce next signed cursor
    string? nextToken = null;
    if (!string.IsNullOrWhiteSpace(page.NextToken))
    {
        var nextCursor = new PageCursor(
            TenantId: tenant.TenantId,
            FilterHash: FilterHasher.Hash(q.Filter),
            Sort: "createdAt:asc",
            LastKey: page.NextToken, // lastKey from data layer
            IssuedUtc: DateTimeOffset.UtcNow);

        nextToken = cursorProtector.Protect(nextCursor);
    }

    return Results.Ok(new
    {
        items,
        page = new
        {
            limit = take,
            nextPageToken = nextToken,
            count = page.Items.Count
        }
    });
})
.RequireRateLimiting("exports-tenant")
.RequireAuthorization(AuthzPolicies.ReportsReadPolicyName)
.WithOpenApi();



app.MapGet("api/v1/raw-records/ABAC", async (
    HttpContext http,
    [AsParameters] RawQuery q,
    IRawDataService dataSvc,
    ISyntheticIdService synth,
    ClaimsPrincipal user) =>
{
    var tenantId = user.FindFirstValue("tid");
    if (string.IsNullOrWhiteSpace(tenantId))
        return Results.Forbid(); // or 401/403 per your preference

    var take = Math.Clamp(q.Limit ?? 100, 1, 100);

    var page = await dataSvc.QueryAsync(
        tenantId,
        q.Filter,
        q.NextPageToken,
        take,
        http.RequestAborted);

    var items = page.Items.Select(r =>
    {
        var shape = FieldProjector.ToApiShape(r, synth);
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
.RequireRateLimiting("exports-tenant")
.RequireAuthorization(AuthzPolicies.DocumentsReadPolicyName)
.WithOpenApi();


app.MapGet("api/v1/raw-records/ABAC/early-rejection-cheap", async (
    HttpContext http,
    [AsParameters] RawQuery q,
    IRawDataService dataSvc,
    ISyntheticIdService synth,
    ClaimsPrincipal user) =>
{
    var tenantId = user.FindFirstValue("tid");
    if (string.IsNullOrWhiteSpace(tenantId))
        return Results.Forbid(); // or 401/403 per your preference

    var take = Math.Clamp(q.Limit ?? 100, 1, 100);

    // ✅ validate before hitting data layer
    var v = RawQueryValidator.Validate(q.Filter, q.NextPageToken, take);
    if (!v.ok)
    {
        return Results.BadRequest(new
        {
            error = "invalid_query",
            message = v.error
        });
    }

    var page = await dataSvc.QueryAsync(
        tenantId,
        q.Filter,
        q.NextPageToken,
        take,
        http.RequestAborted);

    var items = page.Items.Select(r =>
    {
        var shape = FieldProjector.ToApiShape(r, synth);
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
.RequireRateLimiting("exports-tenant")
.RequireAuthorization(AuthzPolicies.DocumentsReadPolicyName)
.WithOpenApi();



app.MapPost("/security/revoke-token", async (
    string jti,
    ITokenRevocationStore store,
    IOptions<TokenHardeningOptions> opt,
    CancellationToken ct) =>
{
    // Revoke for the max age window (+ skew)
    var ttl = TimeSpan.FromMinutes(opt.Value.MaxAccessTokenAgeMinutes + 5);
    await store.RevokeAsync(jti, ttl, ct);
    return Results.Ok(new { revoked = true, jti, ttlMinutes = ttl.TotalMinutes });
})
//.RequireAuthorization("AdminOnly")//
.RequireAuthorization(AuthzPolicies.ReportsReadPolicyName)
.WithOpenApi();



app.MapPost("/api/v1/orders", async (
    ClaimsPrincipal user,
    CreateOrderRequest req,
    CancellationToken ct) =>
{
    // validate input (type/range/etc.)
    if (string.IsNullOrWhiteSpace(req.ProductId) || req.ProductId.Length > 64)
        return Results.BadRequest(new { error = "invalid_product" });

    if (req.Quantity < 1 || req.Quantity > 100)
        return Results.BadRequest(new { error = "invalid_quantity" });

    // TODO: create order (DB) — must be deterministic per idempotency key
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


app.Run();

public sealed record PageCursor(
    string TenantId,
    string? FilterHash,
    string Sort,          // e.g. "createdAt:asc"
    string LastKey,       // e.g. last InternalId or createdAt+id
    DateTimeOffset IssuedUtc);

public sealed record CreateOrderRequest(string ProductId, int Quantity);

// Quien implemente RawQuery usa limit cursor
public record RawQuery(string? Filter, int? Limit, string? NextPageToken);
public sealed record SearchQuery(
    string? Query,
    string[]? Channels,
    DateTimeOffset? FromUtc,
    DateTimeOffset? ToUtc,
    int? Limit,
    string? NextPageToken);
