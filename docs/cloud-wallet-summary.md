# Cloud Wallet Architecture Summary (Issue #444)

This document summarizes the intent and outcomes discussed in GitHub issue adorsys/didcomm-mediator-rs#444 (“Design an architecture diagram of Cloud Wallet”), including linked references.

## Project overview

The issue focuses on defining a **Cloud Wallet** architecture aligned with EU digital identity initiatives and **OpenID4VC** protocols, emphasizing a **split wallet architecture**:

- **UI client** (web/native) where the user interacts and gives consent.
- **Remote wallet backend API** providing wallet functions (issuance/presentation handling, credential lifecycle, encrypted storage, key management).

A recurring theme is scope discipline for a prototype: focus on the remote UI↔API interaction and core wallet functions, and avoid over-engineering (e.g., full OIDC protection for the API was considered too heavy for the prototype timeline).

## Use cases

### Credential issuance (OpenID4VCI)

The wallet should support receiving credentials from external issuers via **OpenID for Verifiable Credential Issuance (OpenID4VCI)**, covering:

- **Authorization Code Flow**
- **Pre-Authorized Code Flow**

Important details called out in the discussion:

- Issuance should be modeled as **initiated from the UI**, because that remote interaction is central to the cloud wallet.
- The design should include **how the UI obtains/handles an access token** (or how that is mediated through the wallet backend).
- **Credential offers can contain multiple credentials**; the UI should allow the user to select which credentials to retrieve.
- Nonce handling should follow the spec (nonce is requested at the **Nonce Endpoint**, not at credential-offer dereference time).

### Credential presentation / verification (OpenID4VP implied)

The wallet should support presenting credentials/proofs to external verifiers (OID4VP implied by the proposed “adapter” components and the verification flow diagrams):

- Receive a presentation request.
- Let the user select credential(s)/data to present.
- Generate a presentation/proof and return it to the verifier.

## Key entities / components

The diagrams and review comments imply the following component model.

### In wallet scope

- **Wallet Backend API**
- **OpenID4VCI Adapter** (issuance)
- **OID4VP Adapter** (presentation)
- **Credential Lifecycle** (import, store, list, update status, delete)
- **Presentation & Proof Engine** (possibly a subcomponent of the OID4VP adapter)
- **Encrypted Storage** (credentials + wallet state)
- **Key Management** (key generation/storage/use for signing and holder binding)

### Outside wallet scope (ecosystem actors)

- **External Issuers**
- **External Verifiers**
- **Revocation/Status Lists** (primarily issuer/verifier responsibility; wallet may only need a client capability for status checking)
- **Trust establishment frameworks** (explicitly discussed as out-of-scope to implement in the cloud wallet prototype)

## Requirements (implied)

### Functional requirements

- **Split architecture support**
  - Distinct UI actor with explicit user consent/selection steps.
  - Backend responsible for protocol interactions, storage, proofs, and key usage.

- **Issuance (OpenID4VCI)**
  - Support authorization code and pre-authorized code flows.
  - Model UI initiation, access token handling, nonce endpoint usage.
  - Support user selection when a credential offer contains multiple credentials.

- **Presentation / verification (OID4VP implied)**
  - Handle presentation requests and generate proofs/presentations.
  - Keep “trust enforcement/establishment” out of the wallet implementation unless explicitly required later.

- **Credential management**
  - Encrypted storage.
  - Credential lifecycle operations.

- **Key management**
  - Secure key handling appropriate for a cloud wallet backend.

### Non-functional requirements / constraints

- **Prototype delivery speed**
  - Avoid overly complex security integration early (e.g., OIDC for the API was deemed excessive for the prototype timeline).

- **Scope clarity**
  - Diagrams should visually differentiate in-scope vs out-of-scope components.
  - Provide a legend and short descriptions for each component.

- **Interoperability**
  - Align with emerging EU wallet specifications and OpenID4VC standards.

## Roadmap (implied by the issue)

- **1. Architecture clarification**
  - Add legend/definitions and scope boundaries.
  - Strengthen links between adapters, credential lifecycle, encrypted storage, and key management.

- **2. Flow completeness**
  - Issuance: model UI initiation, token acquisition, nonce endpoint, multi-credential offers; cover authorized + pre-authorized flows.
  - Verification: keep a distinct UI actor; remove/relocate trust establishment if out-of-scope.

- **3. Prototype security approach**
  - Choose a pragmatic API protection strategy suitable for early delivery.

- **4. Incremental implementation**
  - Implement storage, lifecycle, and key management first.
  - Integrate protocol adapters (OID4VCI, OID4VP).
  - Add status checking client capability if needed (without hosting lists).

## Key references mentioned in the issue

- OpenID4VCI spec: <<https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html>>
- EU Digital Identity Wallet RFCs: <<https://github.com/EWC-consortium/eudi-wallet-rfcs>>
- EU context (Business Wallets proposal): <<https://digital-strategy.ec.europa.eu/en/library/proposal-regulation-establishment-european-business-wallets>>
