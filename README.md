# MultiTenantApi.Secure (.NET 8)

This project is a hardened, GitHub-ready sample of a **multi-tenant** ASP.NET Core **Minimal API** secured for:
- Entra ID (Azure AD) multi-tenant JWT validation
- Scope + AppRole authorization
- Field-level data exposure control
- Deterministic pseudonymous identifiers (HMAC)
- Rate limiting + audit logging
- Defense-in-depth headers and HTTPS enforcement

## Run
```bash
dotnet restore
dotnet run --project MultiTenantApi/MultiTenantApi.csproj
```

## Configure
Edit `MultiTenantApi/appsettings.json`:

- `AzureAd:Audience` => `api://{API_CLIENT_ID}`
- `AzureAd:ClientId` => `{API_CLIENT_ID}`
- `MultiTenant:AllowedTenants` => list of allowed `tid`
- `SyntheticId:KeyBase64` => 32-byte random key (Base64). Store in a secret store.

## Endpoints
- `GET /health` (anonymous)
- `GET /whoami` (auth)
- `GET /documents` (requires delegated scope Documents.Read)
- `GET /reports` (requires delegated scope Reports.Read.All OR app role Reports.Read.All)
- `GET /v1/raw-data` (export, rate limited)
- `GET /v1/export/metadata/call-records` (export metadata, rate limited)
- `GET /v1/export/call-records` (export data, rate limited)

