# OpenID for Verifiable Credential Issuance with Authorization Server

> Reference implementation of OID4VCI-compliant issuance with decoupled Auth Server

## 📌 Overview

This project delivers a **modular, production-ready Authorization Server** purpose-built for **OpenID for Verifiable Credential Issuance (OID4VCI)** workflows.

While the existing OID4VCI Credential Issuer handles basic, prototype-level authorization internally, this work cleanly separates that responsibility by introducing a **dedicated Authorization Server**. The issuer is now focused solely on credential generation, with all access control, grant issuance, and token validation delegated to the new Auth Server.

This system supports **secure, standards-compliant issuance of Verifiable Credentials (VCs)** and is designed for integration with modern digital wallets. It includes:

- 🔐 **Pre-Authorized Code Flow** – Enables issuance without user login
- 🛡️ **DPoP-bound Access Tokens** – Proof-of-possession enforcement ([RFC 9449](https://www.rfc-editor.org/rfc/rfc9449.html))
- 📄 **Authorization Details** – Credential-specific authorization rules ([RFC 9396](https://www.rfc-editor.org/rfc/rfc9396.html))
- 🧾 **Attestation Support** – Embed verified claims directly into issued credentials
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

## 🛠️ Key Features & Requirements Mapping

| #   | Feature                      | Component            | Description                                                   |
| --- | ---------------------------- | -------------------- | ------------------------------------------------------------- |
| 1   | Credential update & re-issue | Credential Issuer    | Revoked credential can be reissued; old version deleted.      |
| 2   | Credential cleanup           | Cron + DB            | Periodic cleanup of expired credential (soft or hard delete). |
| 3   | Refresh Token issued         | Auth Server          | Every access token comes with a refresh token.                |
| 4   | Refresh Token rotation       | Auth Server          | One-time-use refresh tokens; replaced with each request.      |
| 5   | Decoupled authorization      | Auth Server + Config | Tokens validated externally or by config-swappable AS.        |
| 6   | `/nonce` endpoint            | Credential Issuer    | Required for OID4VCI Draft 15; prevents nonce reuse.          |

---

## 🧩 Component Architecture

```mermaid
graph TD
  Wallet -->|GET /credential_offer| Issuer[OID4VC Issuer]
  Wallet -->|POST /token| AuthServer[Authorization Server]
  Wallet -->|POST /credential| Issuer
  Wallet -->|GET /nonce| Issuer
  Issuer -->|POST /grants/pre-authorization-code| AuthServer
  Issuer -->|POST /introspect| AuthServer
  AuthServer --> DB[(PostgreSQL)]
```

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
    Note over Wallet, AuthorizationServer: Includes:<br/>- pre-authorized_code<br/>- DPoP JWT<br/>- client_attestation JWT
  alt Token Request Valid
    AuthorizationServer->>Attestation Provider: Verify attestation (Firebase / App Attest)
    AuthorizationServer->>DB: Store access_token with jkt + attestation
    AuthorizationServer-->>Wallet: access_token, refresh_token
  else Token Request Invalid
    AuthorizationServer-->>Wallet: HTTP 400 (invalid_request)
  end
  Wallet->>CredentialIssuer: GET /nonce
  CredentialIssuer-->>Wallet: nonce
  Wallet->>CredentialIssuer: POST /credential
    Note over Wallet, CredentialIssuer: Includes:<br/>- access_token<br/>- DPoP JWT<br/>- credential proof (with /nonce)
  alt Credential Request Valid
    CredentialIssuer->>AuthorizationServer: POST /introspect
    AuthorizationServer->>DB: Validate token, return jkt + attestation
    AuthorizationServer-->>CredentialIssuer: token + attestation + jkt
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

| Component            | Validates                                                                                                                                                                           |
| -------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Authorization Server | - Pre-auth code<br/>- DPoP JWT (proof-of-possession)<br/>- Attestation JWT<br/>- Refresh token (secondary enforcement via rotation; validated for `used=false` and `revoked=false`) |
| Credential Issuer    | - Introspection (active token, jkt match)<br/>- Nonce proof                                                                                                                         |

---

### 📦 Notes

- Attestation result is stored **in `access_token.attestation`**
- DPoP `jkt` thumbprint is stored in `access_token.cnf_jkt`
- `/credential` endpoint uses `/introspect` to retrieve and validate both
- Wallets use Firebase App Check to handle both Android and iOS attestation

---

## 🧾 Attestation-Based Client Authentication

### ✅ Overview

Attestation ensures that credential requests come from trusted wallet apps on secure devices, helping prevent misuse by blocking tampered, emulated, or unauthorized clients.

This implementation supports Attestation-Based Client Authentication (ABCA) as outlined in the IETF draft:
[OAuth Attestation-Based Client Authentication](https://datatracker.ietf.org/doc/draft-ietf-oauth-attestation-based-client-auth/)

Attestation enables wallets or clients to prove properties about themselves—such as app integrity or device trustworthiness—during token or credential issuance. These claims are cryptographically verifiable and can influence credential access policies.

The wallet provider generates an attestation credential (e.g., Firebase App Check JWT for Android/iOS) and includes it as the client_attestation header in the /token request. The Authorization Server verifies this using Firebase’s REST API and decides whether to trust the wallet based on configurable trust policies (e.g., auto_trust or allow_list). The issuance of attestation credentials is handled by the wallet provider and is out of scope for this system.

---

### 🧾 Firebase App Check Attestation (Android & iOS)

This project supports **attestation-based client authentication** using [Firebase App Check](https://firebase.google.com/docs/app-check), which works on both:

- **Android** (via **Play Integrity API**)
- **iOS** (via **Apple App Attest**)

Wallets use platform-specific APIs under the hood, but both produce a signed **App Check JWT**, which is submitted to the Authorization Server and verified via Firebase’s REST API.

---

### ✅ Attestation Flow

1. Wallet app integrates Firebase App Check.
2. On startup or request, wallet obtains an **App Check token** (JWT) from Firebase via the wallet provider.
3. Wallet includes the token as `client_attestation` when calling `/token`.
4. Authorization Server verifies the token using Firebase’s REST API.
5. If valid, the result is stored and can influence credential authorization.

```mermaid
sequenceDiagram
    participant Wallet
    participant WalletProvider
    participant AuthServer
    participant Firebase
    Wallet->>WalletProvider: Request attestation credential
    WalletProvider->>Firebase: Get App Check token
    Firebase-->>WalletProvider: JWT attestation token
    WalletProvider-->>Wallet: JWT attestation token
    Wallet->>AuthServer: POST /token + client_attestation header + DPoP
    AuthServer->>Firebase: Verify JWT via REST API
    alt Attestation Valid
    Firebase-->>AuthServer: Token valid
    AuthServer->>DB: Store attestation result
    AuthServer-->>Wallet: access_token + refresh_token
    else Attestation Invalid
    Firebase-->>AuthServer: Token invalid
    AuthServer-->>Wallet: HTTP 400 (invalid_request)
    end
```

---

### 🧾 Sample `client_attestation` Field

**Included in `/token` request:**

```http
POST /token
Content-Type: application/x-www-form-urlencoded
DPoP: <signed DPoP JWT>
client_attestation: eyJhbGciOiJSUzI1NiIs...
grant_type=urn:ietf:params:oauth:grant-type:pre-authorized_code&
pre-authorized_code=abc123
```

---

### 🔍 Backend Verification

**Verify using Firebase REST API:**

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

---

### 🔒 Authorization Rules

- ✅ Allow credentials only for verified Firebase apps
- 🔐 Enforce known app package IDs or Apple team IDs
- 🚫 Block requests from rooted/jailbroken/emulated devices
- 🔎 Log attestation type (Play Integrity vs App Attest) for analytics or auditing

---

## 🔐 Attestation Trust Policy

### 🧭 Trust Decision Logic

In addition to Firebase App Check verification, a configurable trust policy can be employed by the **Credential Issuer** based on attestation metadata. This enables selective issuance to trusted wallets only.

### ⚙️ Trust Policy Flow

1. **Attestation Verification** – Performed by the Authorization Server via Firebase REST API.
2. **Trust Decision** – Made by the Credential Issuer after `introspect`, using:
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

    Wallet->>AuthServer: GET /.well-known/openid-credential-issuer
    AuthServer-->>Wallet: Metadata (token/credential endpoints)

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
    CredentialIssuer-->>Wallet: nonce, expires_in
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

---

### 🔐 `POST /token`

Exchanges a pre-authorized code or refresh token for an access token and new refresh token. For refresh token requests, the Authorization Server validates that the token is unused (`used=false`) and not revoked (`revoked=false`) before issuing a new access token and rotating the refresh token. The `user_pin` parameter is optional and only required if `user_pin_required` is `true` in the credential offer, providing an additional layer of security for specific use cases (e.g., high-value credentials).

**Request**

```http
POST /token
Content-Type: application/x-www-form-urlencoded
DPoP: <signed DPoP JWT>
client_attestation: eyJhbGciOiJSUzI1NiIs...
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
  "expires_in": 600,
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

- HTTP 400 (invalid_request): Invalid pre-authorized code, DPoP JWT, or attestation JWT.
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
  "iss": "https://auth.example.com"
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
    "credential_issuer": "https://auth.example.com",
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
  "expires_in": 300
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
  "jwks_uri": "https://auth.example.com/jwks",
  "introspection_endpoint": "https://auth.example.com/introspect"
}
```

### 🔍 Error Handling

- Standard OAuth2 errors: `invalid_token`, `expired_token`, `invalid_grant`, etc.
- DPoP errors: `invalid_dpop_proof`, `replay_detected` (see [DPoP Support](#dpop-support)).
- Nonce errors: `invalid_request` for invalid or expired nonces, `too_many_requests` for exceeding rate limits (see [Nonce Replay Prevention Controls](#nonce-replay-prevention-controls)).
- Attestation errors: `invalid_request` for invalid or unverified attestation JWTs (see [Attestation-Based Client Authentication](#attestation-based-client-authentication)).

---

## 🗄️ Database Schema Diagram

Note: this project uses PostgreSQL as persistence engine, and **singular table names** for consistency and readability.

```mermaid
erDiagram
  ACCESS_TOKEN ||--|{ REFRESH_TOKEN : rotated_by
  SUBJECT ||--o{ PRE_AUTH_CODE : issued
  SUBJECT ||--o{ ACCESS_TOKEN : manages
  SUBJECT ||--o{ REFRESH_TOKEN : manages
  SUBJECT ||--o{ DPOP_JTI : manages

  SUBJECT {
    INT id PK
    JSONB metadata
    TIMESTAMPTZ created_at
    TIMESTAMPTZ updated_at
  }

  PRE_AUTH_CODE {
    INT id PK
    INT subject_id FK
    TEXT code
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
    TEXT token
    TIMESTAMPTZ issued_at
    TIMESTAMPTZ expires_at
    BOOLEAN revoked
    TEXT cnf_jkt
    JSONB metadata
    JSONB attestation
  }

  REFRESH_TOKEN {
    INT id PK
    INT subject_id FK
    INT access_token_id FK
    TEXT token
    TIMESTAMPTZ issued_at
    TIMESTAMPTZ expires_at
    BOOLEAN used
    BOOLEAN revoked
    JSONB metadata
  }


  DPOP_JTI {
    INT id PK
    INT subject_id FK
    TEXT jti
    TEXT htm
    TEXT htu
    TEXT cnf_jkt
    TIMESTAMPTZ issued_at
    TIMESTAMPTZ expires_at
  }

  NONCE {
    INT id PK
    UUID credential_id FK
    TEXT value
    BOOLEAN used
    TIMESTAMPTZ issued_at
    TIMESTAMPTZ expires_at
  }
```

---

## Enhancements & Security Notes

- **Logging**: Audit issuance, revocation, refresh events.
- **Rate Limiting**: Throttle abuse or brute-force attempts.
- **Token Format**: Access tokens are JWTs with claims (`aud`, `exp`, `cnf`, etc.).
- **Token Expiration**: Based on Solution Architecture Design (SAD) default settings.
- **DPoP Key Lifecycle**: Clients manage DPoP key pairs; rotate if compromised.
- **CORS**: Restrict cross-origin requests where applicable.

## Terminology

- **JWT (JSON Web Token)**: A compact, signed token format for secure data exchange (RFC 7519).
- **JWK (JSON Web Key)**: A JSON representation of a cryptographic key (RFC 7517).
- **JKT (JSON Web Key Thumbprint)**: A base64url-encoded hash of a JWK, used to uniquely identify a client’s public key (RFC 7638). In this system, JKT is used in DPoP and attestation flows.
- **JTI (JSON Web Token ID)**: A unique identifier for a JWT, used to prevent replay in DPoP flows.
- **DPoP (Demonstration of Proof-of-Possession)**: A mechanism to bind access tokens to a client’s private key, ensuring only the authorized client can use the token (RFC 9449).
- **Attestation**: A cryptographically verifiable claim about a client’s properties (e.g., app integrity), provided by a wallet provider and verified by the Authorization Server.
- **Pre-authorized Code**: A one-time-use code issued by the Authorization Server to enable credential issuance without user login in the OID4VCI flow.
