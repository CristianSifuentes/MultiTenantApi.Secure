using Mapster;
using Mapster.Models;
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
using Microsoft.Win32;
using MultiTenantApi.Common;
using MultiTenantApi.Infrastructure; // JsonWebToken (faster parser)
using MultiTenantApi.Mapping;
using MultiTenantApi.Middleware;
using MultiTenantApi.Models;
using MultiTenantApi.Security;
using MultiTenantApi.Security.IdempotencyStore;
using MultiTenantApi.Security.ProblemDetails;
using MultiTenantApi.Services;
using MultiTenantApi.Services.CacheService;
using MultiTenantApi.Services.HMAC;
using MultiTenantApi.Services.HttpCache;
using MultiTenantApi.Services.JobStore;
using Serilog;
using Serilog.Events;
using Serilog.Filters;
using System;
using System.ComponentModel;
using System.Diagnostics;
using System.Diagnostics.Metrics;
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


builder.Host.UseSerilog((ctx, lc) =>
{
    lc.ReadFrom.Configuration(ctx.Configuration)
      .MinimumLevel.Override("Microsoft", LogEventLevel.Warning)
      .MinimumLevel.Override("Microsoft.AspNetCore", LogEventLevel.Warning)
      .Enrich.FromLogContext()
      .Enrich.WithProperty("service", "MultiTenantApi")
      .Enrich.WithProperty("env", ctx.HostingEnvironment.EnvironmentName)

      // ✅ Nunca loguear Authorization ni cookies
      .Filter.ByExcluding(Matching.WithProperty<string>("RequestHeader_Authorization", _ => true))
      .Filter.ByExcluding(Matching.WithProperty<string>("RequestHeader_Cookie", _ => true))
      .Filter.ByExcluding(Matching.WithProperty<string>("Authorization", _ => true))

      // ✅ Redact “por si acaso” (si alguien lo mete por error)
      .Destructure.ByTransforming<string>(s =>
          s.Contains("Bearer ", StringComparison.OrdinalIgnoreCase) ? "[REDACTED]" : s)

      .WriteTo.Console();
});

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

//3.2 Middleware global de deprecación por versión
builder.Services.Configure<DeprecationPolicyOptions>(builder.Configuration.GetSection("DeprecationPolicy"));


//✅ AddDistributedMemoryCache()(dev) → solo habilita una implementación de IDistributedCache en memoria, pero no la estás usando para cachear respuestas.
//✅ Multi-tenant (claim tid) + ABAC → base perfecta para cache seguro por tenant.
//✅ Rate limiting → complementa cache (estabilidad).
//✅ AuditMiddleware → cuidado: cache + audit / logging deben coexistir sin filtrar tokens.


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
            // No pongas ex.Message completo: puede contener hints.
            // Haz un mapeo conservador.
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
            // Challenge ocurre en 401; útil para saber por qué se rechazó
            ctx.HttpContext.Items["auth_fail_reason"] ??= "challenge";
            return Task.CompletedTask;
        },
        OnForbidden = ctx =>
        {
            ctx.HttpContext.Items["auth_fail_reason"] ??= "forbidden_policy";
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

    o.OnRejected = async (context, ct) =>
    {
        var http = context.HttpContext;

        // Respuesta RFC7807 consistente
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

// 3.2 Un CacheService pro con “GetOrCreateAsync”
builder.Services.AddSingleton<IApiCache, ApiCache>();

//4) Registrar DI en TU Program.cs (dónde ponerlo)
//En tu bloque de “Mapster + Services (exports)” agrega:
builder.Services.AddSingleton<IJobQueue, InMemoryJobQueue>();
builder.Services.AddSingleton<IJobStore, DistributedJobStore>();
builder.Services.AddHostedService<ExportWorker>();

//6) Auth failures: evita mensajes raros / inconsistentes
builder.Services.AddSingleton<AuthProblemDetailsMiddleware>();

//2) Opción B(enterprise interno): Versionado por Header
builder.Services.AddSingleton<ApiVersioningMiddleware>();

//3.2 Middleware global de deprecación por versión
builder.Services.AddSingleton<DeprecationHeadersMiddleware>();

//4) Observabilidad real: medir uso por versión + tenant + clientAppId
builder.Services.AddSingleton<ApiVersionTelemetryMiddleware>();

//3.1 Middleware “RequestTelemetry” (enterprise)
builder.Services.AddSingleton<RequestTelemetryMiddleware>();

//5.2 Middleware de métricas + señales
builder.Services.AddSingleton<SecuritySignalsMiddleware>();


#endregion




// =====================================================
// Pipeline hardening
// =====================================================
var app = builder.Build();

// Aqui podemos manejar el versionado de apis
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

//2) Opción B(enterprise interno): Versionado por Header
app.UseMiddleware<ApiVersioningMiddleware>();

//4) Observabilidad real: medir uso por versión + tenant + clientAppId
app.UseMiddleware<ApiVersionTelemetryMiddleware>();

//3.1 Middleware “RequestTelemetry” (enterprise)
app.UseMiddleware<RequestTelemetryMiddleware>();

//5.2 Middleware de métricas + señales
app.UseMiddleware<SecuritySignalsMiddleware>();

#endregion


app.UseSwagger();
app.UseSwaggerUI(c =>
{
    c.SwaggerEndpoint("/swagger/v1/swagger.json", "MultiTenantApi.Secure v1");
    c.SwaggerEndpoint("/swagger/v2/swagger.json", "MultiTenantApi.Secure v2");

});

app.UseRateLimiter();
app.UseAuthentication();
// recommended: AFTER UseAuthentication so ctx.User is populated.
app.UseMiddleware<TokenAgeGuardMiddleware>();
app.UseAuthorization();
//6) Auth failures: evita mensajes raros / inconsistentes
app.UseMiddleware<AuthProblemDetailsMiddleware>();

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

    // Opcional: baja ruido de health
    opts.GetLevel = (ctx, _, ex) =>
        ctx.Request.Path.StartsWithSegments("/health") ? Serilog.Events.LogEventLevel.Verbose :
        ex is not null ? Serilog.Events.LogEventLevel.Error :
        Serilog.Events.LogEventLevel.Information;
});

// =====================================================
// Error endpoint (ProblemDetails)
// =====================================================
app.MapGet("/error", (HttpContext ctx) =>
{
    var traceId = ctx.TraceIdentifier;

    return Results.Problem(
        title: "An unexpected error occurred.",
        statusCode: StatusCodes.Status500InternalServerError,
        extensions: new Dictionary<string, object?>
        {
            ["traceId"] = traceId,
            ["errorCode"] = "internal_error"
        });
}).ExcludeFromDescription();

//app.MapGet("/error", (HttpContext ctx) =>
//{
//    // No stack traces, no exception details to clients.
//    // The exception is accessible via IExceptionHandlerFeature if you need it for logging only.

//    return Problem.Create(
//        ctx,
//        status: StatusCodes.Status500InternalServerError,
//        code: ApiErrorCodes.Unexpected,
//        title: "An unexpected error occurred.",
//        detail: "Contact support with the correlationId if the issue persists.");
//})
//.ExcludeFromDescription();
//app.MapGet("/error", (HttpContext ctx) =>
//{
//    // RFC7807 ProblemDetails
//    var traceId = ctx.TraceIdentifier;
//    return Results.Problem(
//        title: "An unexpected error occurred.",
//        statusCode: StatusCodes.Status500InternalServerError,
//        extensions: new Dictionary<string, object?> { ["traceId"] = traceId });
//}).ExcludeFromDescription();



// =====================================================
// Health / diagnostics
// =====================================================
v1.MapGet("/health", () => Results.Ok(new { status = "ok", utc = DateTimeOffset.UtcNow }))
   .AllowAnonymous()
   .WithOpenApi();

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



// =====================================================
// Secure sample endpoints
// =====================================================
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


// ntory of exposed fields (OWASP API9)
// =====================================================
v1.MapGet("/export/metadata/call-records", async (
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
// RAW data export — hardened: rate limiting + safe field projection + synthetic IDs
// =====================================================
v1.MapGet("/raw-records", async (
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
// SEARCH — hardened: ABAC tenant scope + strict validation + cursor pagination
// Threats: OWASP API4 (resource consumption), API1 (BOLA via cross-tenant), scraping/fuzzing
// =====================================================
v1.MapGet("/search", async (
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
            message = v.error,
            traceId = http.TraceIdentifier
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




v1.MapGet("/call-records", async (
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


v1.MapGet("/raw-records/ABAC", async (
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


v1.MapPost("/orders", async (
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

    // ✅ Validación barata ANTES del job (rechazo temprano)
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

    // ✅ 202 Accepted con Location (status)
    var statusUrl = $"/jobs/{jobId}";
    var resultUrl = $"/exports/raw-data/{jobId}";

    http.Response.Headers.Location = statusUrl;
    return Results.Accepted(statusUrl, new StartJobResponse(jobId, statusUrl, resultUrl));
})
.RequireAuthorization(AuthzPolicies.ReportsReadPolicyName)
.RequireRateLimiting("exports-tenant")
.WithOpenApi();


v1.MapGet("/jobs/{id}", async (
    string id,
    HttpContext http,
    IJobStore store,
    ClaimsPrincipal user) =>
{
    var tenantId = user.FindFirstValue("tid");
    if (string.IsNullOrWhiteSpace(tenantId)) return Results.Forbid();

    var job = await store.GetAsync(id, http.RequestAborted);
    if (job is null) return Results.NotFound();

    // ✅ ABAC: el job pertenece al tenant
    if (!string.Equals(job.TenantId, tenantId, StringComparison.Ordinal))
        return Results.Forbid();

    return Results.Ok(job);
})
.RequireAuthorization()
.WithOpenApi();

v1.MapGet("/exports/raw-data/{jobId}", async (
    string jobId,
    HttpContext http,
    IJobStore store,
    ClaimsPrincipal user) =>
{
    var tenantId = user.FindFirstValue("tid");
    if (string.IsNullOrWhiteSpace(tenantId)) return Results.Forbid();

    var job = await store.GetAsync(jobId, http.RequestAborted);
    if (job is null) return Results.NotFound();

    if (!string.Equals(job.TenantId, tenantId, StringComparison.Ordinal))
        return Results.Forbid();

    if (job.State is JobState.Queued or JobState.Running)
        return Results.Accepted($"/jobs/{jobId}", new { status = job.State.ToString() });

    if (job.State == JobState.Failed)
        return Results.Problem(title: "Export failed", detail: job.Error, statusCode: 500);

    if (job.State == JobState.Canceled)
        return Results.Problem(title: "Export canceled", statusCode: 409);

    // ✅ Succeeded: en prod, stream desde blob:
    // return Results.File(stream, "application/json", "export.json");
    return Results.Ok(new { message = "Would download from storage", job.ResultLocation });
})
.RequireAuthorization(AuthzPolicies.ReportsReadPolicyName)
.WithOpenApi();



v1.MapGet("/raw-records/ABAC/early-rejection-cheap", async (
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

v1.MapPost("/security/revoke-token", async (
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


#region endpoints v2
v2.MapGet("/export/metadata/call-records", async (
    HttpContext http,
    ICallRecordService svc,
    IMapper mapper,
    CancellationToken ct,
    ClaimsPrincipal user
    ) =>
{
    var tid = user.FindFirstValue("tid") ?? "unknown";

    var fields = ApiMetadataBuilder.BuildFor<CallRecord>();
    var sampleDomain = await svc.GetSampleAsync(ct);
    var sampleExport = mapper.Map<List<CallRecordExportDto>>(sampleDomain);

    // ✅ ETag input MUST include tenant + version + a stable representation
    var etagInput = $"tenant:{tid}|entity:CallRecord|v1|fields:{fields.Count}|sample:{sampleExport.Count}";
    var etag = HttpCache.ComputeWeakETag(etagInput);

    var response = new EntityMetadataResponse<CallRecordExportDto>(
        EntityName: "CallRecord",
        Version: "v1",
        Fields: fields,
        Sample: sampleExport);

    return HttpCache.ETagOrOk(http, etag, response, maxAgeSeconds: 120);
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
v2.MapGet("/export/call-records", async (
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

v2.MapGet("/raw-records", async (
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


#endregion

#region endpoints v3
v3.MapGet("/raw-records", async (
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
    {
        return Problem.Create(
            http,
            status: StatusCodes.Status400BadRequest,
            code: ApiErrorCodes.InvalidRequest,
            title: "Invalid query.",
            detail: v.error);
    }
    //if (!v.ok)
    //    return Results.BadRequest(new { error = "invalid_query", message = v.error });

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

#endregion

#region endpoints v4

v4.MapGet("api/v4/raw-records", async (
    HttpContext http,
    [AsParameters] RawQuery q,
    IRawDataService dataSvc,
    ISyntheticIdService synth,
    IApiCache cache,
    ClaimsPrincipal user) =>
{
    var tenant = TenantContextFactory.From(user);
    if (string.IsNullOrWhiteSpace(tenant.TenantId))
        return Results.Forbid();

    var take = Math.Clamp(q.Limit ?? 100, 1, 100);

    // ✅ early rejection
    var v = RawQueryValidator.Validate(q.Filter, q.NextPageToken, take);
    if (!v.ok)
        return Results.BadRequest(new { error = "invalid_query", message = v.error });

    var cacheKey = RawCacheKey(tenant.TenantId, q, take);

    // ✅ TTL corto: reduce load, limita staleness
    var cached = await cache.GetOrCreateAsync(
        cacheKey,
        ttl: TimeSpan.FromSeconds(15),
        factory: async ct =>
        {
            var page = await dataSvc.QueryAsync(tenant.TenantId, q.Filter, q.NextPageToken, take, ct);

            var items = page.Items.Select(r =>
            {
                var shape = FieldProjector.ToApiShape(r, synth);
                shape["syntheticId"] = synth.Create("raw", r.InternalId.ToString("N"));
                return shape;
            });

            return new
            {
                items,
                page = new
                {
                    limit = take,
                    nextPageToken = page.NextToken,
                    count = page.Items.Count
                }
            };
        },
        ct: http.RequestAborted);

    // ✅ ETag encima del server cache (doble beneficio)
    var tid = tenant.TenantId;
    var etag = HttpCache.ComputeWeakETag($"{tid}|{cacheKey}");
    return HttpCache.ETagOrOk(http, etag, cached, maxAgeSeconds: 10);
})
.RequireRateLimiting("exports-tenant")
.RequireAuthorization(AuthzPolicies.ReportsReadPolicyName)
.WithOpenApi();
#endregion



//En tu caso con Entra, “login” vive fuera, pero aplica perfecto a:
/// password - reset / request
/// send - otp
/// invite
/// onboarding / start
//(flujos sensibles OWASP API6)









static string RawCacheKey(string tenantId, RawQuery q, int take)
{
    return $"raw:v1:tenant:{tenantId}:limit:{take}:filter:{q.Filter ?? ""}:cursor:{q.NextPageToken ?? ""}";
}








//Middleware setea X-Tenant-Id en response
//Proxy define cache key por X-Tenant-Id + path + query
//app.Use(async (ctx, next) =>
//{
//    await next();

//    // Después de auth, si hay tid, lo reflejas
//    var tid = ctx.User.FindFirstValue("tid");
//    if (!string.IsNullOrWhiteSpace(tid))
//        ctx.Response.Headers["X-Tenant-Id"] = tid;
//});

app.Use(async (ctx, next) =>
{
    // ✅ Programar headers ANTES de que empiece la respuesta
    ctx.Response.OnStarting(() =>
    {
        var tid = ctx.User.FindFirstValue("tid");
        if (!string.IsNullOrWhiteSpace(tid))
            ctx.Response.Headers["X-Tenant-Id"] = tid;

        return Task.CompletedTask;
    });

    await next();
});


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



//2) Diseño: “Start Export” → 202 + JobId
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
