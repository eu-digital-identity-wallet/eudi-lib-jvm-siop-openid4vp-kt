# SIOPv2 & OpenID4VP flows


## Functionality in scope

On a high level the functions that need to be supported by wallet

1. Issuance of a self-attested  `id-token`
2. Presentation of a verifiable credential `vp-token`
3. Combination of the two above

```mermaid
sequenceDiagram
    Verifier -->> Wallet : Process AuthorizationRequest
    Wallet -->> SDK : Resolve AuthorizationRequest 
    SDK -->> SDK: resolution Either[Problem, ResolvedAuthorizationRequest]
    SDK -->> SDK: tryToAnswer Either[Problem, CandidateResponse]
    SDK -->> Wallet : Either[Problem, CandidateResponse]
    Wallet -->> User : Ask consensus and choices
    User --> Wallet: Consensus
    Wallet -->> SDK: Form response
    SDK -->> Wallet : AuthorizationResponse
    Wallet -->> Verifier: AuthorizationResponse
```

```mermaid
classDiagram
    class AuthorizationRequest
    class ResolvedAuthorizationRequest
    class IdTokenRequest
    class VpTokenRequest
    class IdAndVpTokenRequest
    ResolvedAuthorizationRequest <|-- IdTokenRequest
    ResolvedAuthorizationRequest <|-- VpTokenRequest
    ResolvedAuthorizationRequest <|-- IdAndVpTokenRequest
    class CandidateResponse
    class CandidateIdTokenResponse
    class CandidateVpTokenResponse
    class CandidateIdAndVpTokenResponse
    CandidateResponse<|--CandidateIdTokenResponse
    CandidateResponse<|--CandidateVpTokenResponse
    CandidateResponse<|--CandidateIdAndVpTokenResponse
```