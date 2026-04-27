# OID4VCI Spec Compliance Review — `POST /api/v1/issuance/start`

## Executive Summary

The implementation correctly handles the core OID4VCI credential offer resolution flow, including PKCE, PAR, metadata discovery, and SSRF protections. However, several spec compliance gaps and security concerns were identified — most notably a CSRF vulnerability on the authorization callback and missing server-side session expiry enforcement.

---

## Critical Issues (Must Fix)

### 1. CSRF Vulnerability — Missing `state` Validation on Authorization Callback ✅ FIXED

**Severity:** High  
**Spec Reference:** RFC 6749 §4.1.1, OID4VCI §5.2  
**Location:** `cloud-wallet-openid4vc/src/issuance/client/mod.rs:450-480`

**Problem:**  
`parse_authz_callback()` extracts the `state` parameter from the authorization response but never validates it against the `state` value sent in the original authorization request. Per RFC 6749, this is mandatory to prevent CSRF attacks.

**Fix Applied:**  
Added `expected_state: &str` parameter to `parse_authz_callback()` and validates the returned state against it:

```rust
pub fn parse_authz_callback(
    &self,
    redirect_uri: &str,
    expected_state: &str,
) -> Result<AuthorizationCallback> {
    // ... parse response ...
    if response.state.as_deref() != Some(expected_state) {
        return Err(ClientError::validation(
            "state mismatch: possible CSRF attack",
        ));
    }
    Ok(AuthorizationCallback::Success(response))
}
```

---

### 2. Session Expiry Not Enforced Server-Side ✅ FIXED

**Severity:** Medium  
**Spec Reference:** OID4VCI §4.1.1 (pre-authorized codes MUST be short-lived)  
**Location:** `src/server/handlers/issuance.rs:44`, `src/session/data.rs:11-20`

**Problem:**  
The handler calculated `expires_at` and returned it in the response, but never stored it in the `IssuanceSession` struct. The session had no expiry tracking, meaning expired sessions could still be used for credential operations.

**Fix Applied:**  
1. Added `expires_at: OffsetDateTime` to `IssuanceSession` struct
2. Stored it during session creation with a default 1-hour TTL
3. Added `is_expired()` method to `IssuanceSession`
4. Added `ExpiredSession` variant to `SessionError`
5. `transition()` now checks expiry before allowing state changes
6. Handler now uses `session.expires_at` instead of computing a separate value

---

## Medium Issues (Should Fix)

### 3. Pre-Authorized Code Stored in Plain Session ✅ FIXED

**Severity:** Medium  
**Spec Reference:** OID4VCI §4.1.1 (pre-authorized codes are single-use, short-lived tokens)  
**Location:** `src/session/data.rs:15`

**Problem:**  
`IssuanceSession` stored the full `CredentialOffer` which contained `grants.pre_authorized_code.pre_authorized_code` — a sensitive single-use token. If the session store (Redis, memory, etc.) was compromised, these tokens could be replayed.

**Fix Applied:**  
Replaced `offer: ParsedOffer` (which was `CredentialOffer`) with `offer: SessionOfferData`. The `SessionOfferData` struct extracts non-sensitive fields and intentionally excludes the `pre_authorized_code` string value from the `SessionPreAuthorizedCodeGrant` struct. `From` implementations convert `CredentialOffer` → `SessionOfferData` during session creation.

```rust
pub struct SessionOfferData {
    pub credential_issuer: Url,
    pub credential_configuration_ids: Vec<String>,
    pub grants: SessionGrantsData,
}

pub struct SessionPreAuthorizedCodeGrant {
    pub tx_code: Option<TxCode>,
    pub authorization_server: Option<Url>,
    // pre_authorized_code intentionally excluded
}
```

---

### 4. Flow Determination Misses Pre-Authorized Code in AS Metadata ✅ FIXED

**Severity:** Medium  
**Spec Reference:** OID4VCI §4.1.1 (when grants absent, determine from AS metadata)  
**Location:** `cloud-wallet-openid4vc/src/issuance/client/mod.rs:1040-1065`

**Problem:**  
When the credential offer had no `grants` field, `determine_flow_from_as_metadata()` only checked for `authorization_code` in `grant_types_supported`. It completely ignored `urn:ietf:params:oauth:grant-type:pre-authorized_code`, causing valid pre-authorized flows to fail with `NoSupportedGrantType`.

**Fix Applied:**  
Added check for pre-authorized code grant type before falling back to authorization code:

```rust
fn determine_flow_from_as_metadata(as_metadata: &AuthorizationServerMetadata) -> Result<IssuanceFlow> {
    const PRE_AUTH_CODE: &str = "urn:ietf:params:oauth:grant-type:pre-authorized_code";
    const AUTHZ_CODE: &str = "authorization_code";

    let supported = as_metadata.grant_types_supported.as_deref().unwrap_or_default();

    if supported.iter().any(|g| g == PRE_AUTH_CODE) {
        return Ok(IssuanceFlow::PreAuthorizedCode {
            pre_authorized_code: String::new(),
            tx_code: None,
        });
    }
    // ... authorization_code fallback ...
}
```

---

### 5. Fragile String-Based Error Mapping ✅ FIXED

**Severity:** Low  
**Location:** `src/server/handlers/issuance.rs:107-139`

**Problem:**  
The `map_client_error` function used string matching (`msg.contains("issuer metadata")`) to differentiate error types. This was fragile — any change to error message formatting would break the mapping.

**Fix Applied:**  
Added typed error variants to `ClientError`:

```rust
pub enum ClientError {
    #[error("issuer metadata discovery failed: {message}")]
    IssuerMetadataDiscovery { message: Cow<'static, str> },

    #[error("authorization server metadata discovery failed: {message}")]
    AsMetadataDiscovery { message: Cow<'static, str> },
    // ...
}
```

Updated `From<Error>` impl to produce the specific variants, and updated `map_client_error` to match on variants directly instead of string matching.

---

## Low Issues (Nice to Have)

### 6. Metadata Fetched Before Flow Decision ✅ FIXED

**Severity:** Low  
**Spec Reference:** OID4VCI §4.1.1  
**Location:** `cloud-wallet-openid4vc/src/issuance/client/mod.rs:357-430`

**Problem:**  
`resolve_offer_with_metadata()` fetched both issuer and AS metadata before determining the flow type. If the offer already contained explicit grants, the AS metadata fetch was unnecessary network overhead and increased SSRF surface area.

**Fix Applied:**  
Added `try_determine_flow_from_offer()` method that determines flow from offer grants alone. `resolve_offer_with_metadata()` now only fetches AS metadata when grants are absent or ambiguous. `ResolvedOfferContext.as_metadata` is now `Option<AuthorizationServerMetadata>` to reflect that it may not always be populated.

---

### 7. No Rate Limiting on Metadata Discovery ⏳ DEFERRED

**Severity:** Low  
**Location:** `cloud-wallet-openid4vc/src/issuance/client/mod.rs:256-285, 291-347`

**Problem:**  
Metadata discovery calls have a 10-second timeout but no rate limiting. An attacker could provide a malicious `credential_issuer` URL pointing to a slow server, causing resource exhaustion.

**Recommendation:** Add request rate limiting at the handler level or implement a circuit breaker pattern for metadata discovery calls.

**Status:** Deferred — issue #6 reduces the SSRF surface by avoiding unnecessary AS metadata fetches when grants are present in the offer. Rate limiting should be added as a separate improvement.

---

### 8. `redirect_uri` Not Validated Against AS Metadata ⏳ DEFERRED

**Severity:** Low  
**Spec Reference:** OID4VCI §5.1  
**Location:** `cloud-wallet-openid4vc/src/issuance/client/mod.rs:418`

**Problem:**  
The configured `redirect_uri` is sent without checking if it matches any URI registered in the AS metadata. While this is typically a registration-time concern, runtime validation would catch misconfigurations early.

**Status:** Deferred — this is typically a configuration-time concern. Runtime validation could be added as a future enhancement.

---

## Implementation Priority

| Priority | Issue | Effort | Risk if Unaddressed | Status |
|----------|-------|--------|---------------------|--------|
| P0 | #1 CSRF state validation | Low | Security vulnerability | ✅ Fixed |
| P0 | #2 Session expiry enforcement | Medium | Token replay, stale sessions | ✅ Fixed |
| P1 | #3 Pre-authorized code storage | Medium | Sensitive token exposure | ✅ Fixed |
| P1 | #4 Flow determination gap | Low | Valid issuers fail | ✅ Fixed |
| P2 | #5 Typed error variants | Low | Maintenance burden | ✅ Fixed |
| P2 | #6 Metadata fetch optimization | Low | Performance/SSRF surface | ✅ Fixed |
| P3 | #7 Rate limiting | Medium | DoS vector | ⏳ Deferred |
| P3 | #8 redirect_uri validation | Low | Misconfiguration detection | ⏳ Deferred |

---

## Testing Recommendations

Add integration tests for:
1. CSRF protection — verify callback rejection on state mismatch
2. Session expiry — verify expired sessions return 410
3. Pre-authorized code isolation — verify token not stored in plain session
4. Flow determination — test AS metadata with only `pre-authorized_code` grant
5. Error mapping — verify each `ClientError` variant maps to correct HTTP status
6. Metadata optimization — verify AS metadata is not fetched when offer has explicit grants
