# What changed and why (Security)

This hardened version focuses on OWASP API Security Top-10 themes.

## 1) Issuer validation (multi-tenant)
**Problem:** Many samples disable issuer validation (`ValidateIssuer=false`) which allows *any* tenant to call you.
**Fix:** `TenantAllowListIssuerValidator` enforces `tid` allow-list (unless explicitly enabled for dev).

Mitigates: Broken Authentication / Broken Authorization.

## 2) Audience hardening
**Problem:** Accepting tokens not intended for your API leads to privilege confusion.
**Fix:** `ValidAudiences` includes only your configured audience(s).

Mitigates: Broken Authentication.

## 3) Deterministic pseudonymous identifiers (HMAC)
**Problem:** Exposing internal IDs enables correlation and data exfiltration.
**Fix:** `ISyntheticIdService` uses HMAC-SHA256 with a secret key from configuration/secret store.
Also uses **length-prefix canonical encoding** to avoid delimiter ambiguity.

Mitigates: Excessive Data Exposure, BOLA support (reduces exploit value).

## 4) Field-level allowlist projection + masking
**Problem:** Returning whole objects easily leaks internal fields.
**Fix:** `FieldProjector` exposes only `[ApiField(Expose=true)]` and applies masking by strategy.
Reflection metadata is cached to avoid per-request overhead.

Mitigates: Excessive Data Exposure (API3), Data exfiltration.

## 5) Rate limiting partitioned by identity
**Problem:** Fixed global limits are easy to bypass; unlimited exports allow resource exhaustion.
**Fix:** Global limiter partitions by `oid/appid/ip` and adds stricter "exports" limiter.

Mitigates: Unrestricted Resource Consumption (API4), brute-force, scraping, DoS.

## 6) Audit logging + correlation IDs (without secrets)
**Problem:** Logging tokens/PII creates its own breach.
**Fix:** `AuditMiddleware` records minimal audit metadata and correlation IDs; never logs Authorization.

Mitigates: Security logging failures, incident response gaps.

## 7) HTTPS enforcement + security headers
**Problem:** Missing HTTPS / weak headers enable MITM and browser-based abuse.
**Fix:** HSTS + HTTPS redirect + a set of safe security headers.

Mitigates: MITM, clickjacking, content sniffing.

## 8) Exception handling with ProblemDetails
**Problem:** Stack traces / internal details in responses help attackers.
**Fix:** Centralized exception handler that returns RFC7807 ProblemDetails.

Mitigates: information leakage.

