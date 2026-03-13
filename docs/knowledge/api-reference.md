# API Reference — cloud-identity-wallet

## Overview

Cloud Identity Wallet provides a REST API for verifiable credential management, implementing OpenID4VCI for issuance and OpenID4VP for presentation.

- **Base URL:** TBD
- **Versioning:** URL path (e.g., `/v1/...`)
- **Content-Type:** `application/json`
- **Character Encoding:** UTF-8

## Authentication

| Method | Header | Format |
|--------|--------|--------|
| Bearer Token | `Authorization` | `Bearer <token>` |

### Obtaining a Token

Authentication flows are handled via OpenID4VCI/OpenID4VP protocols. The wallet backend mediates token acquisition from external issuers.

## OpenID4VCI Endpoints (Issuance)

**Spec**: <https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html>

### Supported Flows

| Flow | Description |
|------|-------------|
| Authorization Code | Standard OAuth 2.0 authorization code flow |
| Pre-Authorized Code | Out-of-band code exchange for access token |

### Credential Offer

| Method | Path                 | Description              | Auth Required |
|--------|----------------------|--------------------------|---------------|
| GET    | `/credential-offer`  | Resolve credential offer | No            |

**Credential Offer Structure:**

```json
{
  "credential_issuer": "https://issuer.example.com",
  "credential_configuration_ids": ["UniversityDegreeCredential"],
  "grants": {
    "authorization_code": {
      "issuer_state": "opaque-state-string"
    },
    "urn:ietf:params:oauth:grant-type:pre-authorized_code": {
      "pre_authorized_code": "short-lived-code",
      "tx_code": {
        "input_mode": "numeric",
        "length": 4,
        "description": "Enter the code sent via SMS"
      }
    }
  }
}
```

**Fields:**

| Field | Required | Description |
|-------|----------|-------------|
| `credential_issuer` | Yes | URL of the Credential Issuer |
| `credential_configuration_ids` | Yes | Array of credential configuration IDs to offer |
| `grants` | No | Object with supported grant types |

**Grant Types:**

- `authorization_code`: Standard OAuth 2.0 flow with optional `issuer_state`
- `urn:ietf:params:oauth:grant-type:pre-authorized_code`: Pre-authorized flow with required `pre_authorized_code` and optional `tx_code`

**Key Concepts:**

- Credential offers can contain multiple credentials; UI should allow user selection
- Nonce is requested at dedicated Nonce Endpoint, not at credential-offer dereference time
- Access token handling is mediated through wallet backend
- `tx_code.description` max length is 300 characters

### Credential Endpoint

| Method | Path             | Description                       | Auth Required |
|--------|------------------|-----------------------------------|---------------|
| POST   | `/credential`    | Request credential with proofs    | Yes           |

**Request Example:**

```json
{
  "format": "vc+sd-jwt",
  "proof": {
    "proof_type": "jwt",
    "jwt": "<proof-jwt>"
  }
}
```

**Response Example:**

```json
{
  "credential": "<credential-jwt>",
  "c_nonce": "fGSGsdfgsdg",
  "c_nonce_expires_in": 86400
}
```

## OpenID4VP Endpoints (Presentation)

**Spec**: <https://openid.net/specs/openid-4-verifiable-presentations-1_0.html>

### Presentation Request

| Method | Path                      | Description                              | Auth Required |
|--------|---------------------------|------------------------------------------|---------------|
| GET    | `/presentation/request`   | Get presentation request from verifier    | No            |

**Key Concepts:**

- Verifier presents a `request_uri` to an Authorization Request Object (JWT)
- User selects credentials/data to present
- Wallet generates presentation/proof and returns VP Token

### Presentation Response

| Method | Path              | Description                      | Auth Required |
|--------|-------------------|----------------------------------|---------------|
| POST   | `/presentation`   | Submit verifiable presentation    | Yes           |

**Response Example:**

```json
{
  "vp_token": "<verifiable-presentation>",
  "presentation_submission": { ... }
}
```

## Credential Formats

### Supported Formats

| Format ID | Description |
|-----------|-------------|
| `vc+sd-jwt` | SD-JWT based verifiable credentials (selective disclosure) |
| `mso_mdoc` | ISO 18013-5 mobile documents (mDL/mdoc) |
| `jwt_vc_json` | JWT-based verifiable credentials (JSON claims) |

### Format-Specific Notes

#### mso_mdoc (ISO mdoc)

- **Namespace-aware claims**: Claims extracted per namespace (e.g., `org.iso.18013-5.1`)
- **Schema validation**: Uses JSON Schema with feature gate `schema-validation`
- **Claims structure**: Different from JWT-based formats

#### vc+sd-jwt

- Selective disclosure capabilities
- Holder binding support

## Credential Lifecycle Endpoints

| Method | Path                      | Description              | Auth Required |
|--------|---------------------------|--------------------------|---------------|
| GET    | `/credentials`            | List stored credentials   | Yes           |
| GET    | `/credentials/{id}`      | Get specific credential   | Yes           |
| DELETE | `/credentials/{id}`      | Delete credential         | Yes           |
| POST   | `/credentials/import`     | Import credential         | Yes           |

## Error Codes

| HTTP Status | Error Code             | Description                               | Resolution                               |
|-------------|------------------------|-------------------------------------------|------------------------------------------|
| 400         | `VALIDATION_ERROR`     | Schema validation failure                 | Check credential format and claims       |
| 400         | `SCHEMA_MISMATCH`      | Credential does not match expected schema | Verify credential structure              |
| 401         | `UNAUTHORIZED`         | Missing or invalid authentication         | Provide valid bearer token               |
| 403         | `FORBIDDEN`            | Insufficient permissions                 | Check tenant/user permissions            |
| 404         | `NOT_FOUND`            | Resource not found                        | Verify resource ID                       |
| 409         | `CONFLICT`             | Credential state conflict                 | Check credential status                  |
| 422         | `UNPROCESSABLE_ENTITY` | Invalid credential format                 | Verify format matches supported types    |
| 429         | `RATE_LIMITED`         | Too many requests                         | Wait and retry                           |
| 500         | `INTERNAL_ERROR`       | Server error                              | Check logs, contact support              |

### Error Response Format

```json
{
  "error": {
    "code": "VALIDATION_ERROR",
    "message": "Human-readable message",
    "details": [
      {
        "field": "claims.org.iso.18013-5.1",
        "message": "Missing required claim"
      }
    ]
  }
}
```

## Rate Limiting

| Tier    | Limit | Window     | Headers                                      |
|---------|-------|------------|----------------------------------------------|
| Default | 100   | per minute | `X-RateLimit-Limit`, `X-RateLimit-Remaining` |

## Pagination

Cursor-based pagination for list endpoints:

**Query Parameters:**

- `cursor`: Pagination cursor
- `limit`: Max items per page (default: 20, max: 100)

**Response Format:**

```json
{
  "items": [...],
  "cursor": "next-page-cursor",
  "has_more": true
}
```

## Webhooks

Webhook events for credential lifecycle:

| Event                  | Description                        |
|------------------------|------------------------------------|
| `credential.issued`    | Credential successfully issued     |
| `credential.stored`    | Credential stored in wallet        |
| `credential.presented` | Credential presented to verifier   |
| `credential.deleted`   | Credential deleted from wallet     |

**Payload Format:**

```json
{
  "event": "credential.issued",
  "timestamp": "2024-01-15T10:30:00Z",
  "data": {
    "credential_id": "uuid",
    "format": "vc+sd-jwt"
  }
}
```
