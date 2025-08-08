# OpenID for Verifiable Credential Issuance with Authorization Server

> Reference implementation of OID4VCI-compliant issuance with decoupled Auth Server

## 📌 Overview

This project delivers a **modular, production-ready Authorization Server** purpose-built for **OpenID for Verifiable Credential Issuance (OID4VCI)** workflows.

While the existing OID4VCI Credential Issuer handles basic, prototype-level authorization internally, this work cleanly separates that responsibility by introducing a **dedicated Authorization Server**. The issuer is now focused solely on credential generation, with all access control, grant issuance, and token validation delegated to the new Auth Server.

This system supports **secure, standards-compliant issuance of Verifiable Credentials (VCs)** and is designed for integration with modern digital wallets. It includes:

- 🔐 **Pre-Authorized Code Flow** – Enables issuance without user login
- 🛡️ **DPoP-bound Access Tokens** – Proof-of-possession enforcement ([RFC 9449](https://www.rfc-editor.org/rfc/rfc9449.html))
- 📄 **Authorization Details** – Credential-specific authorization rules ([RFC 9396](https://www.rfc-editor.org/rfc/rfc9396.html))
- 🧾 **Attestation Support** – Verified by the Credential Issuer using trusted attestation providers, embed verified claims directly into issued credentials
- 🔁 **Refresh Token Rotation** – Mitigates token reuse and supports long-lived sessions
- 🧠 **Token Introspection** – Fine-grained validation with embedded credential metadata
- 🌐 **Metadata Discovery** – Standards-based wallet interoperability via `.well-known` endpoints

### 🔧 Core Components

- **Authorization Server** (FastAPI + Authlib)
- **Credential Issuer** with delegated authorization and introspection integration
- **PostgreSQL** for persistence of grants, tokens, and credential metadata
- **Support for DPoP, Authorization Details, Attestations, Refresh Tokens rotation**

This architecture separates concerns, improves security, enhances extensibility, and provides a scalable foundation for OID4VCI credential issuance in production environments.

---

## 🔗 Multi-Tenancy

The system supports multi-tenancy for data isolation in OID4VCI workflows. The Credential Issuer and Authorization Server use a **database-per-tenant** model, where each tenant has a dedicated PostgreSQL database with the same schema (e.g., `SUBJECT`, `ACCESS_TOKEN`).

**Key Features**:

- **Database-Per-Tenant Model**:

  - Each tenant (identified by `tenant-id`) maps to a separate database (e.g., `tenant1_db`).
  - In single-tenant deployments, non-prefixed endpoints like /token and /credential implicitly use the default tenant (default_db). These endpoints remain compatible with wallets that don't support tenant-prefixed URIs.
  - All tenant databases use the same schema version, managed via Alembic migrations, ensuring consistency across deployments.
  - Enforcement: Tokens must only be used in the context of their issuing tenant. Cross-tenant use will return HTTP 401 (invalid_token).
  - Benefits: Strong isolation, independent scaling, and deployment flexibility across regions and environments.

- **Tenant Configuration**:

  - Mappings stored in a configuration file or central store:

    | Tenant ID | Database URL                  | Firebase Project ID |
    | --------- | ----------------------------- | ------------------- |
    | tenant1   | `postgresql://.../tenant1_db` | `tenant1-firebase`  |
    | tenant2   | `postgresql://.../tenant2_db` | `tenant2-firebase`  |
    | default   | `postgresql://.../default_db` | `default-firebase`  |

  - The firebase_project_id is used for verifying client attestation (optional). If attestation is disabled, this value may be omitted

- **Endpoint Structures**:

  - Multi-Tenant: Prefix with /tenants/{tenant-id}/ (e.g., /tenants/tenant1/token).
  - Single-Tenant: Use non-prefixed endpoints (e.g., /token).
  - Alignment: Matches Credential issuer's /tenants/{tenant-id}/xxx.
  - Resolution: From path for multi-tenant; defaults to "default" for single-tenant.

- **Token Scoping**:

  - Tokens include a realm claim (e.g., "realm": "tenant1").
  - Example Payload:

```json
{
  "sub": "did:example:abcd1234",
  "realm": "tenant1",
  "cnf": {
    "jkt": "base64url-encoded-thumbprint"
  }
}
```

- Validation: Match realm to request context during introspection.

- **Security and Isolation**:

  - Physical separation prevents cross-tenant leakage.
  - Tenant-specific credentials (database users, Firebase projects) and CORS restrictions.
  - Errors: 400 invalid_tenant – Tenant not found

- **Provisioning and Maintenance**:

  - Automate with scripts (e.g., CREATE DATABASE tenant1_db; then schema migration).
  - Migrations: Use Alembic to apply changes across databases.
  - Monitoring: Per-tenant performance monitoring with tools like pg_stat_activity.

---

## 🛠️ Key Features & Requirements Mapping

| #   | Feature                      | Component            | Description                                                   |
| --- | ---------------------------- | -------------------- | ------------------------------------------------------------- |
| 1   | Credential update & re-issue | Credential Issuer    | Revoked credential can be reissued; old version deleted.      |
| 2   | Credential cleanup           | Cron + DB            | Periodic cleanup of expired credential (soft or hard delete). |
| 3   | Refresh Token issued         | Auth Server          | Every access token comes with a refresh token.                |
| 4   | Refresh Token rotation       | Auth Server          | One-time-use refresh tokens; replaced with each request.      |
| 5   | Decoupled authorization      | Auth Server + Config | Tokens validated externally or by config-swappable AS.        |
| 6   | Attestation verification     | Credential Issuer    | Verify client_attestation JWT via Firebase/App Attest         |
| 7   | `/nonce` endpoint            | Credential Issuer    | Required for OID4VCI Draft 15; prevents nonce reuse.          |

---

## 🧩 Component Architecture

```mermaid
graph TD
    subgraph Public
        Wallet[Wallet]
        Firebase[Firebase App Check]
    end

    subgraph DTI
        Issuer[OID4VC Issuer]
        AuthServer[Authorization Server]
        DB1[(Tenant1 DB)]
        DB2[(Tenant2 DB)]
        DBn[(TenantN DB)]
        DBDefault[(Default DB)]
    end

    Wallet -->|/credential_offer| Issuer
    Wallet -->|/token| AuthServer
    Wallet -->|/credential| Issuer
    Wallet -->|/nonce| Issuer

    Issuer -->|/grants/pre-authorized-code| AuthServer
    Issuer -->|/introspect| AuthServer
    Issuer -->|Verify Attestation| Firebase

    AuthServer -->|Store/Retrieve Tenant1| DB1
    AuthServer -->|Store/Retrieve Tenant2| DB2
    AuthServer -->|Store/Retrieve TenantN| DBn
    AuthServer -->|Store/Retrieve Default| DBDefault
```

**Multi-Tenancy Note**: For multi-tenant deployments, endpoints can be prefixed with `/tenants/{tenant-id}/` to route to tenant-specific databases. See the [Multi-Tenancy](#multi-tenancy) section for details on database-per-tenant model, tenant configuration, and token scoping with the `realm` claim.

---

## 🔄 Credential Issuance Flow

This section presents the process for issuing Verifiable Credentials using OpenID for Verifiable Credential Issuance (OID4VCI), covering:

- Pre-authorized code grant registration
- Client attestation (Firebase App Check or App Attest)
- Demonstration of Proof-of-Possession (DPoP)
- Token introspection and credential delivery
- The Wallet requests a nonce from the `/nonce` endpoint to include in the credential proof, ensuring protection against replay attacks (see [Nonce Replay Prevention Controls](#nonce-replay-prevention-controls))
- The Wallet may use a refresh token to obtain a new access token for subsequent credential requests (see [Refresh Token Flow](#refresh-token-flow))

The following flows outline the initial credential issuance and optional refresh token processes.

### 🧬 Initial Credential Issuance Flow

```mermaid
sequenceDiagram
  participant Wallet
  participant CredentialIssuer
  participant AuthorizationServer
  participant DB
  Wallet->>CredentialIssuer: GET /credential_offer
  CredentialIssuer->>AuthorizationServer: POST /grants/pre-authorized-code
  AuthorizationServer->>DB: Store pre-auth-code with subject_id + metadata
  AuthorizationServer-->>CredentialIssuer: pre-authorized-code
  CredentialIssuer-->>Wallet: credential_offer_uri
  Wallet->>AuthorizationServer: POST /token
    Note over Wallet, AuthorizationServer: Includes:<br/>- pre-authorized_code<br/>- DPoP JWT
  alt Token Request Valid
    AuthorizationServer->>DB: Store access_token with jkt
    AuthorizationServer-->>Wallet: access_token, refresh_token
  else Token Request Invalid
    AuthorizationServer-->>Wallet: HTTP 400 (invalid_request)
  end
  Wallet->>CredentialIssuer: GET /nonce
  CredentialIssuer-->>Wallet: nonce
  Wallet->>CredentialIssuer: POST /credential
    Note over Wallet, CredentialIssuer: Includes:<br/>- access_token<br/>- DPoP JWT<br/>- client_attestation JWT<br/>- credential proof (with /nonce)
  alt Credential Request Valid
    CredentialIssuer->>AuthorizationServer: POST /introspect
    AuthorizationServer->>DB: Validate token, return jkt
    AuthorizationServer-->>CredentialIssuer: token + jkt
    CredentialIssuer->>Attestation Provider: Verify attestation (Firebase / App Attest)
    CredentialIssuer-->>Wallet: Verifiable Credential
  else Credential Request Invalid
    CredentialIssuer-->>Wallet: HTTP 400 (invalid_request)
  end
```

---

### 🧬 Refresh Token Flow

The refresh token flow allows wallets to obtain a new access token and refresh token after the initial credential issuance, ensuring long-lived sessions with secure token rotation.

```mermaid
sequenceDiagram
  participant Wallet
  participant AuthorizationServer
  participant DB
  Wallet->>AuthorizationServer: POST /token + refresh_token
  AuthorizationServer->>DB: Validate refresh_token (used=false, revoked=false)
  alt Token Valid
    DB-->>AuthorizationServer: Token valid
    AuthorizationServer->>DB: Mark refresh_token as used, store new refresh_token
    AuthorizationServer-->>Wallet: access_token, new refresh_token
  else Token Invalid
    DB-->>AuthorizationServer: Token invalid or revoked
    AuthorizationServer-->>Wallet: HTTP 401 (invalid_token)
  end
```

---

### 🛡️ Enforcement Points

| Component            | Validates                                                                                                                                                     |
| -------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Authorization Server | - Pre-auth code<br/>- DPoP JWT (proof-of-possession)<br/>- Refresh token (secondary enforcement via rotation; validated for `used=false` and `revoked=false`) |
| Credential Issuer    | - Introspection (active token, jkt match)<br/>- Attestation JWT (via Firebase/App Attest)<br/>- Nonce proof                                                   |

---

### 📦 Notes

- Attestation is **verified by the Credential Issuer** during the `/credential` request.
- DPoP `jkt` thumbprint is stored in `access_token.cnf_jkt`; proof-of-possession is also validated by the Credential Issuer.
- The `/credential` endpoint uses `/introspect` to validate the access token and retrieve embedded claims (e.g., `cnf.jkt`), then performs its own DPoP checks.
- Wallets use **Firebase App Check** to generate `client_attestation` JWTs on Android and iOS, which are passed to the Credential Issuer for validation.

---

## 🧾 Attestation Validation

### ✅ Overview

Attestation ensures that credential requests come from trusted wallet apps on secure devices, helping prevent misuse by blocking tampered, emulated, or unauthorized clients.

This implementation supports Attestation-Based Client Authentication (ABCA) as outlined in the IETF draft:
[OAuth Attestation-Based Client Authentication](https://datatracker.ietf.org/doc/draft-ietf-oauth-attestation-based-client-auth/)

Attestation enables wallets or clients to prove properties about themselves—such as app integrity or device trustworthiness—during token or credential issuance. These claims are cryptographically verifiable and can influence credential access policies.

The wallet provider generates an attestation credential (e.g., Firebase App Check JWT for Android/iOS). The wallet includes it in the /credential request as the client_attestation field. The Credential Issuer verifies the token and decides whether to issue the credential based on trust policies (e.g., auto_trust or allow_list).

---

### 🧾 Firebase App Check Attestation (Android & iOS)

This project supports **attestation-based client authentication** using [Firebase App Check](https://firebase.google.com/docs/app-check), which works on both:

- **Android** (via **Play Integrity API**)
- **iOS** (via **Apple App Attest**)

Wallets use platform-specific APIs under the hood, but both produce a signed **App Check JWT**, which is submitted to the Credential Issuer, and verified by the Issuer using Firebase’s REST API.

---

### ✅ Attestation Flow

Attestations (e.g., Firebase App Check tokens, device claims) are generated and signed by the wallet or mobile platform provider. These signed JWTs are passed by the wallet in the client_attestation field during the credential request.

The Authorization Server is responsible for OAuth2 flows only (e.g., pre-authorized_code, DPoP access tokens) and does not validate attestations.

The Credential Issuer validates the attestation JWT by verifying its signature, extracting trusted metadata, and applying a configurable trust policy to decide whether to issue the requested credential.

```mermaid

sequenceDiagram
    participant Wallet
    participant WalletProvider
    participant AuthServer as Authorization Server
    participant Issuer as Credential Issuer
    participant Firebase

    Wallet->>WalletProvider: Request attestation credential
    WalletProvider->>Firebase: Get App Check token
    Firebase-->>WalletProvider: JWT attestation token
    WalletProvider-->>Wallet: JWT attestation token
    Wallet->>AuthServer: Request access token (pre-authorized code + DPoP)
    AuthServer-->>Wallet: access_token
    Wallet->>Issuer: Credential request + client_attestation JWT
    Issuer->>Firebase: Verify attestation via REST API
    alt Attestation Valid
        Firebase-->>Issuer: Token valid
        Issuer->>Wallet: Verifiable Credential
    else Attestation Invalid
        Firebase-->>Issuer: Token invalid
        Issuer-->>Wallet: Error (e.g., 400 invalid_attestation)
    end
```

> _Note: Attestation is only evaluated at the credential issuance step._

---

### 🧾 Sample Credential Request with client_attestation

**Included in `/credential` request:**

```http
POST /credential
Authorization: Bearer <access_token>
DPoP: <signed DPoP JWT>
Content-Type: application/json

{
  "format": "vc+sd-jwt",
  "type": "OntarioBusinessCard",
  "client_attestation": "eyJhbGciOiJSUzI1NiIs...",   // add this
  "proof": { "proof_type": "jwt", "jwt": "..." }
}
```

---

### 🔍 Verify using Firebase REST API (performed by Credential Issuer):

```http
POST https://firebaseappcheck.googleapis.com/v1/projects/{project-id}/apps/{app-id}:verifyAppCheckToken
Authorization: Bearer {service-account-access-token}
Content-Type: application/json

{
  "app_check_token": "eyJhbGciOiJSUzI1NiIs..."
}
```

**Successful response:**

```json
{
  "token": {
    "ttl": "300s",
    "issuedAtTime": "2025-07-17T18:00:00Z"
  }
}
```

- ✅ Allow credentials only for verified Firebase apps
- 🔐 Enforce known app package IDs or Apple team IDs
- 🚫 Block requests from rooted/jailbroken/emulated devices
- 🔎 Log attestation type (Play Integrity vs App Attest) for analytics or auditing

---

### 🧭 Trust Decision Logic

The **Credential Issuer**, after verifying the attestation token, applies a trust policy to determine if the wallet is authorized to receive a credential.

### ⚙️ Trust Policy Flow

1. **Attestation Verification** – Performed by the Credential Issuer via Firebase REST API.
2. **Trust Decision** – Made using:
   - `attestation.sub`: Subject identifier in the attestation token.
   - `cnf.jkt`: Client's DPoP key thumbprint.
3. **Trust Policy Modes**:
   - `auto_trust`: Accept all verified attestation tokens.
   - `allow_list`: Only issue credentials if both `sub` and `jkt` are found in a trusted list.

### 📋 Allow List Structure

```json
{
  "trusted_clients": [
    {
      "sub": "firebase_app_id_123",
      "jkt": "base64url_jkt_thumbprint"
    },
    {
      "sub": "apple_team_id_abc",
      "jkt": "base64url_jkt_thumbprint"
    }
  ]
}
```

### 📘 OpenID4VCI Attestation Credential Metadata

Per [Appendix E](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#appendix-E) of the OpenID4VCI specification:

```json
{
  "format": "jwt_vc",
  "types": ["VerifiableCredential", "Attestation"],
  "trust_framework": "firebase_app_check",
  "evidence": {
    "type": "app_attestation",
    "sub": "firebase_app_id_123",
    "jkt": "base64url_jkt_thumbprint",
    "timestamp": "2025-07-17T18:00:00Z"
  }
}
```

---

### 📘 References

- Firebase App Check: [https://firebase.google.com/docs/app-check](https://firebase.google.com/docs/app-check)
- REST Verification API: [https://firebase.google.com/docs/reference/app-check/rest/v1](https://firebase.google.com/docs/reference/app-check/rest/v1)
- Apple App Attest: [https://developer.apple.com/documentation/devicecheck/implementing_app_attest](https://developer.apple.com/documentation/devicecheck/implementing_app_attest)
- Play Integrity API: [https://developer.android.com/google/play/integrity](https://developer.android.com/google/play/integrity)

---

## 🔐 DPoP (Demonstration of Proof-of-Possession) Support

### ✅ Overview

Demonstration of Proof-of-Possession (DPoP) ensures that access tokens are bound to a client’s private key, preventing unauthorized use of stolen tokens (RFC 9449).

### ✅ DPoP Support

- **Required for /token and /credential**: DPoP is mandatory for both the `/token` and `/credential` endpoints, ensuring that only the client possessing the private key can use the issued access token.
- **Access tokens include cnf.jkt thumbprint**: The access token includes a `cnf.jkt` claim, containing the JSON Web Key Thumbprint (JKT) of the client’s public key, binding the token to the client’s DPoP key pair.
- **Replay protection enforced using jti**: The `jti` (JSON Web Token ID) claim in the DPoP JWT is validated to ensure uniqueness, preventing replay attacks by rejecting reused DPoP proofs.
- **Credential Issuer matches DPoP proof with cnf.jkt**: The Credential Issuer verifies that the DPoP JWT provided in the `/credential` request matches the `cnf.jkt` in the access token, ensuring proof-of-possession.

**Note**: See [Terminology](#terminology) for definitions of JKT and JTI, and [Error Handling](#error-handling) for DPoP-specific errors (`invalid_dpop_proof`, `replay_detected`).

### 🧬 Token Binding Flow with DPoP

```mermaid
sequenceDiagram
  participant Wallet
  participant AuthServer
  participant Issuer
  Wallet->>AuthServer: POST /token + DPoP JWT
  AuthServer-->>Wallet: access_token (with cnf.jkt)
  Wallet->>Issuer: POST /credential + DPoP JWT
  Issuer-->>Wallet: Return VC
```

### 🛠️ Implementation Steps

1. **Client Generates DPoP Key Pair**:

   - Public JWK is included in `DPoP` JWT header.
   - JWT includes: `htm`, `htu`, and `jti` claims.
     - `htm`: HTTP method (e.g., "POST")
     - `htu`: HTTP URI (e.g., "https://issuer.example.com/credential")
     - `jti`: Unique identifier for the DPoP JWT, used to prevent replay.

2. **Client Sends DPoP Header with `/token` Request**:

   ```http
   POST /token
   Authorization: DPoP <signed JWT>
   ```

3. **Authorization Server Validates**:

   - Signature
   - `htu` and `htm` match
   - `jti` is unique (prevents replay)
   - Extracts JWK thumbprint (`cnf.jkt`) for access token

4. **Issued Access Token Contains `cnf` Claim**:

   ```json
   {
     "cnf": {
       "jkt": "<base64url JWK thumbprint>"
     }
   }
   ```

5. **Credential Issuer Enforces DPoP on `/credential`**:
   - Re-validates proof-of-possession

---

## 🔄 RFC 7591/7592: Dynamic Client Registration

### ✅ Overview

Credential Issuer, acting on behalf of a trusted program owner, performs client registration internally when generating a credential offer. It ensures:

- Only authorized credential offers are issued
- Wallets are provisioned with appropriate scopes and authorization context
- Client metadata is linked to the credential issuance transaction (e.g. tx_code, supported_cred_id)

The Credential Issuer registers the subject of the credential using `subject_id`. This ID may be UUID or another privacy-preserving identifier. It is distinct from any external system identifiers.

### 🔧 Registration Flow

```mermaid
sequenceDiagram
    participant Wallet
    participant CredentialIssuer
    participant AuthServer
    participant DB

    Wallet->>CredentialIssuer: GET /credential_offer
    CredentialIssuer->>CredentialIssuer: Generate unique subject_id and tx_code

    CredentialIssuer->>AuthServer: POST /grants/pre-authorized-code (subject_id, supported_cred_id, tx_code)
    AuthServer->>DB: Store pre-auth-code, link to subject_id

    AuthServer-->>CredentialIssuer: pre-auth-code
    CredentialIssuer-->>Wallet: credential_offer_uri (QR or link)

    Wallet->>CredentialIssuer: GET /.well-known/openid-credential-issuer
    CredentialIssuer-->>Wallet: Metadata (token/credential endpoints)

    Wallet->>AuthServer: POST /token (pre-auth-code + DPoP)
    AuthServer->>DB: Validate code, bind DPoP
    AuthServer-->>Wallet: access_token + refresh_token

    Wallet->>CredentialIssuer: POST /credential + DPoP
    CredentialIssuer->>AuthServer: POST /introspect
    AuthServer-->>CredentialIssuer: token is active + authorization_details
    CredentialIssuer-->>Wallet: Verifiable Credential
```

---

## 🔐 Nonce Replay Prevention Controls

To prevent replay attacks in the credential issuance process, the `/nonce` endpoint provides a unique, time-bound nonce for use in the `/credential` request proof. The following controls ensure robust nonce management:

- Nonces are stored in the `NONCE` table with a unique `value` field (indexed for efficient lookup), a `used` flag, and an `expires_at` timestamp. The `credential_id` field links to the `SUBJECT.subject_id` (a UUID) to scope nonces to a specific subject.
- The Credential Issuer validates that the nonce exists, is unused (`used=false`), and has not expired (`expires_at > CURRENT_TIMESTAMP`).
- After successful validation, the nonce is marked as `used` to prevent reuse.
- If the nonce is invalid (nonexistent, already used, or expired), the Credential Issuer returns an HTTP 400 response with an `invalid_request` error code and a descriptive message (e.g., "Nonce is invalid or expired").
- Expired nonces are periodically cleaned up via a cron job to maintain database efficiency.
- The `/nonce` endpoint is rate-limited to 10 requests per minute per client IP to prevent abuse and denial-of-service attacks.

**Note**: Replay protection for DPoP JWTs is enforced using the `jti` claim, complementing nonce-based replay prevention (see [DPoP Support](#dpop-support)).

### 🧬 Nonce Flow

```mermaid
sequenceDiagram
    participant Wallet
    participant CredentialIssuer
    participant DB
    Wallet->>CredentialIssuer: GET /nonce
    CredentialIssuer->>DB: Store nonce (value, expires_at, used=false)
    DB-->>CredentialIssuer: Nonce stored
    CredentialIssuer-->>Wallet: nonce, expires_at
    Wallet->>CredentialIssuer: POST /credential + nonce in proof
    CredentialIssuer->>DB: Validate nonce (exists, used=false, not expired)
    alt Nonce Valid
    DB-->>CredentialIssuer: Nonce valid
    CredentialIssuer->>DB: Mark nonce as used
    CredentialIssuer-->>Wallet: Verifiable Credential
    else Nonce Invalid
    DB-->>CredentialIssuer: Nonce invalid or expired
    CredentialIssuer-->>Wallet: HTTP 400 (invalid_request)
    end
    Note over CredentialIssuer,DB: Periodic cleanup of expired nonces
```

## 📘 API Endpoints

### ✅ API Endpoint Summary

#### Authorization Server Endpoints

| Endpoint                            | Method | Auth              | Description                          |
| ----------------------------------- | ------ | ----------------- | ------------------------------------ |
| `/token`                            | POST   | DPoP              | Token exchange (pre-auth or refresh) |
| `/introspect`                       | POST   | ClientId + Secret | Token validation                     |
| `/grants/pre-authorized-code`       | POST   | ClientId + Secret | Pre-authorization_code grant.        |
| `/.well-known/openid-configuration` | GET    | None              | Auth Server Metadata discovery       |

#### Credential Issuer Endpoints

| Endpoint                                | Method | Auth          | Description                      |
| --------------------------------------- | ------ | ------------- | -------------------------------- |
| `/credential_offer`                     | GET    | None          | Offer URI with pre-auth code     |
| `/credential`                           | POST   | Bearer + DPoP | Request VC                       |
| `/nonce`                                | GET    | None          | Nonce for credential proof       |
| `/.well-known/openid-credential-issuer` | GET    | None          | OID4VC Issuer metadata discovery |

**Multi-Tenancy Note**: For multi-tenant deployments, endpoints can be prefixed with `/tenants/{tenant-id}/` to route to tenant-specific databases. See the [Multi-Tenancy](#multi-tenancy) section for details on database-per-tenant model, tenant configuration, and token scoping with the `realm` claim.

---

### 🔐 `POST /token`

Exchanges a pre-authorized code or refresh token for an access token and new refresh token. For refresh token requests, the Authorization Server validates that the token is unused (`used=false`) and not revoked (`revoked=false`) before issuing a new access token and rotating the refresh token. The `user_pin` parameter is optional and only required if `user_pin_required` is `true` in the credential offer, providing an additional layer of security for specific use cases (e.g., high-value credentials).

**Request**

```http
POST /token
Content-Type: application/x-www-form-urlencoded
DPoP: <signed DPoP JWT>
grant_type=urn:ietf:params:oauth:grant-type:pre-authorized_code&
pre-authorized_code=abc123&
user_pin=1234
```

**Response**

```json
{
  "access_token": "eyJhbGciOi...",
  "refresh_token": "xyz456",
  "token_type": "Bearer",
  "expires_at": "iso-8601-datetime",
  "scope": "openid vc_authn vc_business_card",
  "authorization_details": [
    {
      "type": "openid_credential",
      "format": "vc+sd-jwt",
      "types": ["VerifiableCredential", "OntarioBusinessCard"]
    }
  ],
  "cnf": {
    "jkt": "base64url-encoded-thumbprint"
  }
}
```

**Errors**:

- HTTP 400 (invalid_request): Invalid pre-authorized code, DPoP JWT.
- HTTP 401 (invalid_token): Invalid or revoked refresh token.

---

### 📤 `POST /introspect`

Used by the Credential Issuer to verify bearer tokens before releasing credential.

**Request**

```http
POST /introspect
Authorization: Basic base64(client_id:client_secret)
Content-Type: application/x-www-form-urlencoded

token=eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...
token_type_hint=access_token
```

**Response**

```json
{
  "active": true,
  "scope": "openid vc_authn vc_business_card",
  "subject_id": "c26fe7f5-6bd8-41c5-b0af-c2f555ec89f7",
  "token_type": "Bearer",
  "exp": 1721031600,
  "iat": 1721028000,
  "sub": "did:example:abcd1234",
  "authorization_details": [
    {
      "type": "openid_credential",
      "format": "vc+sd-jwt",
      "types": ["VerifiableCredential", "OntarioBusinessCard"]
    }
  ],
  "cnf": {
    "jkt": "QmFzZTY0ZW5jb2RlZFRodW1icHJpbnQ="
  },
  "iss": "https://auth.example.com",
  "realm": "tenant1"
}
```

**Errors**:

- HTTP 401 (invalid_client): Invalid client credentials.
- HTTP 400 (invalid_request): Invalid token or token type hint.

---

### 🔐 POST /grants/pre-authorized-code

Request pre-authorized code. The `external_user_ref` field links the subject to an external identity provider (e.g., Okta) for integration with existing user management systems, but it is optional and not required for credential issuance

**Request:**

```http
POST /grants/pre-authorized-code
Content-Type: application/json
Authorization: Bearer internal-access-token
```

**Request body:**

```http
HTTP/1.1 200 OK
Content-Type: application/json
```

```json
{
  "subject_id": "c26fe7f5-6bd8-41c5-b0af-c2f555ec89f7",
  "metadata": {
    "tx_code": "abc-001",
    "supported_cred_id": "OntarioBusinessCard",
    "external_user_ref": "okta|00u1abcxyz"
  }
}
```

**Response:**

```json
{
  "grant_type": "urn:ietf:params:oauth:grant-type:pre-authorized_code",
  "pre-authorized_code": "xyz456"
}
```

---

### 📤 `POST /credential`

Request a credential using an access token.

**Request**

```http
POST /credential
Authorization: Bearer eyJhbGciOi...
DPoP: <signed DPoP JWT>
Content-Type: application/json

{
  "format": "vc+sd-jwt",
  "type": "OntarioBusinessCard",
  "proof": {
    "proof_type": "jwt",
    "jwt": "eyJ0eXAiOiJKV1Q..."
  }
}
```

**Response**

```json
{
  "format": "vc+sd-jwt",
  "credential": "eyJhbGciOiJFZERTQSJ9...sig", // SD-JWT compact format
  "issuer_signed_attestations": {
    "alg": "ES256",
    "kid": "did:example:issuer#keys-1"
  }
}
```

**Errors**:

- HTTP 400 (invalid_request): Invalid access token, DPoP JWT, or nonce proof.

---

### 🪪 `GET /credential_offer`

Returns the credential offer URI with embedded pre-authorized code.

**Request**

```http
GET /credential_offer
```

**Response**

```json
{
  "credential_offer_uri": "openid-credential-offer://?credential_offer=..."
}
```

Decoded credential_offer:

```json
{
  "credential_offer": {
    "credential_issuer": "https://issuer.example.com",
    "grants": {
      "urn:ietf:params:oauth:grant-type:pre-authorized_code": {
        "pre-authorized_code": "abc123",
        "user_pin_required": false
      }
    },
    "authorization_details": [
      {
        "type": "openid_credential",
        "format": "vc+sd-jwt",
        "types": ["VerifiableCredential", "OntarioBusinessCard"]
      }
    ]
  }
}
```

---

### 🔄 `GET /nonce`

Provides a unique, time-bound nonce for use in the `/credential` request proof to prevent replay attacks. See [Nonce Replay Prevention Controls](#nonce-replay-prevention-controls) for details on replay prevention and security measures.

**Request**

```http
GET /nonce
```

**Response**

```json
{
  "nonce": "123456789abcdef",
  "expires_at": "iso-8601-datetime"
}
```

**Errors**

HTTP 429 (Too Many Requests): Returned if the rate limit of 10 requests per minute per client IP is exceeded (see [Nonce Replay Prevention Controls](#nonce-replay-prevention-controls)).

---

### 🔄 `GET /.well-known/openid-credential-issuer`

**Request**

```http
GET /.well-known/openid-credential-issuer
```

**Response**

```json
{
  "credential_issuer": "https://issuer.example.com",
  "authorization_server": "https://auth.example.com",
  "token_endpoint": "https://auth.example.com/token",
  "credential_endpoint": "https://issuer.example.com/credential",
  "nonce_endpoint": "https://issuer.example.com/nonce",
  "nonce_lifetime": 300,
  "credentials_supported": {
    "OntarioBusinessCard": {
      "format": "vc+sd-jwt",
      "proof_types_supported": ["jwt"],
      "cryptographic_binding_methods_supported": ["did"],
      "cryptographic_suites_supported": ["ES256"]
    }
  }
}
```

### 🔄 `GET /.well-known/openid-configuration`

**Request**

```http
GET /.well-known/openid-configuration
```

**Response**

```json
{
  "issuer": "https://auth.example.com",
  "token_endpoint": "https://auth.example.com/token",
  "token_endpoint_auth_methods_supported": ["none"],
  "grant_types_supported": [
    "urn:ietf:params:oauth:grant-type:pre-authorized_code"
  ],
  "authorization_details_types_supported": ["openid_credential"],
  "jwks_uri": "https://auth.example.com/jwks",
  "introspection_endpoint": "https://auth.example.com/introspect"
}
```

### 🔍 Error Handling

- Standard OAuth2 errors: `invalid_token`, `expired_token`, `invalid_grant`, etc.
- DPoP errors: `invalid_dpop_proof`, `replay_detected` (see [DPoP Support](#dpop-support)).
- Nonce errors: `invalid_request` for invalid or expired nonces, `too_many_requests` for exceeding rate limits (see [Nonce Replay Prevention Controls](#nonce-replay-prevention-controls)).
- Attestation errors: `invalid_attestation` or `invalid_request`, returned by the Credential Issuer if the `client_attestation` JWT is missing, malformed, expired, or fails verification (see [Attestation Validation](#attestation-validation)).

---

## 🗄️ Database Schema Diagram

This project uses PostgreSQL as the persistence engine. For consistency and readability, we adhere to the following conventions:

- Singular table names: Aligns with modern ORM practices (e.g., SQLAlchemy) and avoids pluralization ambiguities.
- Timestamps: All tables include created_at and updated_at fields (using TIMESTAMPTZ) for auditing and versioning, defaulting to CURRENT_TIMESTAMP on insert/update.
- Foreign Keys: Use ON DELETE CASCADE for child records (e.g., tokens tied to a subject) to prevent orphans, and ON UPDATE CASCADE for ID propagation.
- Indexing: Key fields are indexed for performance. The last column in the schema diagram indicates:
  - PK: Primary Key
  - FK: Foreign Key
  - UK: Unique index for uniqueness enforcement and fast lookups (maps to PostgreSQL CREATE UNIQUE INDEX)
  - INDEX: Non-unique index for fast lookups (maps to PostgreSQL CREATE INDEX)

```mermaid
erDiagram
    ACCESS_TOKEN ||--|{ REFRESH_TOKEN : rotated_by
    SUBJECT ||--o{ PRE_AUTH_CODE : issued
    SUBJECT ||--o{ ACCESS_TOKEN : manages
    SUBJECT ||--o{ REFRESH_TOKEN : manages
    SUBJECT ||--o{ DPOP_JTI : manages
    SUBJECT ||--o{ NONCE : manages

    SUBJECT {
        INT id PK
        JSONB metadata
        TIMESTAMPTZ created_at
        TIMESTAMPTZ updated_at
    }

    PRE_AUTH_CODE {
        INT id PK
        INT subject_id FK
        TEXT code UK
        TEXT user_pin
        BOOLEAN user_pin_required
        JSONB authorization_details
        TIMESTAMPTZ expires_at
        TIMESTAMPTZ issued_at
        BOOLEAN used
    }

    ACCESS_TOKEN {
        INT id PK
        INT subject_id FK
        TEXT token UK
        TIMESTAMPTZ issued_at
        TIMESTAMPTZ expires_at
        BOOLEAN revoked
        TEXT cnf_jkt "INDEX"
        JSONB metadata
    }

    REFRESH_TOKEN {
        INT id PK
        INT subject_id FK
        INT access_token_id FK
        TEXT token UK
        TIMESTAMPTZ issued_at
        TIMESTAMPTZ expires_at
        BOOLEAN used
        BOOLEAN revoked
        JSONB metadata
    }

    DPOP_JTI {
        INT id PK
        INT subject_id FK
        TEXT jti UK
        TEXT htm
        TEXT htu
        TEXT cnf_jkt
        TIMESTAMPTZ issued_at
        TIMESTAMPTZ expires_at
    }

    NONCE {
        INT id PK
        UUID credential_id FK
        TEXT value UK
        BOOLEAN used
        TIMESTAMPTZ issued_at
        TIMESTAMPTZ expires_at
    }
```

---

## 🛡️ Enhancements & Security Notes

- **Logging**: Audit issuance, revocation, refresh events.
- **Rate Limiting**: Throttle abuse or brute-force attempts.
- **Token Format**: Access tokens are JWTs with claims (`aud`, `exp`, `cnf`, etc.).
- **Token Expiration**: Based on Solution Architecture Design (SAD) default settings.
- **DPoP Key Lifecycle**: Clients manage DPoP key pairs; rotate if compromised.
- **CORS**: Restrict cross-origin requests where applicable.

## 📘 Terminology

- **JWT (JSON Web Token)**: A compact, signed token format for secure data exchange (RFC 7519).
- **JWK (JSON Web Key)**: A JSON representation of a cryptographic key (RFC 7517).
- **JKT (JSON Web Key Thumbprint)**: A base64url-encoded hash of a JWK, used to uniquely identify a client’s public key (RFC 7638). In this system, JKT is used in DPoP and attestation flows.
- **JTI (JSON Web Token ID)**: A unique identifier for a JWT, used to prevent replay in DPoP flows.
- **DPoP (Demonstration of Proof-of-Possession)**: A mechanism to bind access tokens to a client’s private key, ensuring only the authorized client can use the token (RFC 9449).
- **Attestation**: A cryptographically verifiable claim about a client’s properties (e.g., app integrity), provided by a wallet provider and verified by the Credential Issuer.
- **Pre-authorized Code**: A one-time-use code issued by the Authorization Server to enable credential issuance without user login in the OID4VCI flow.
- Realm: A logical identifier that maps a token to a specific tenant.
