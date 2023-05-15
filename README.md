# SIOPv2 OpenID4VP 

This is a Kotlin library, targeting JVM, that supports the SIOPv2 (draft 12) and OpenId4VP (draft 18) protocols.
In particular, the library focus on the wallet's role and in addition focuses on the 
usage of those two protocols as they are constraint by ISO 23220-4 and ISO-18013-7




## Usage

### Resolve an authorization request URI 

Wallet receives an OAUTH2 Authorization request, formed by the Verifier, that may represent either 

- a SIOPv2 authentication request, or 
- a OpenID4VP authorization request,  
- or a combined SIOP & OpenID4VP request

In the same device  scenario the aforementioned authorization request reaches the wallet in terms of 
a deep link. Similarly, in the cross device scenario, the request would be obtained via scanning a QR Code.

Regardless of the scenario, wallet must take the URI (of the deep link or the QR Code) that represents the 
authorization request and ask the SDK to validate the URI (that is to make sure that it represents one of the supported
requests mentioned aforementioned) and in addition gather from Verifier additional information that may be included by
reference (such as `presentation_definition_uri`, `client_metadata_uri` etc)

```kotlin
import eu.europa.ec.euidw.openid4vp.*

val walletConfig: WalletOpenId4VPConfig =  ...
val authorizationRequestUri : String = ...


val resolution = SiopOpenId4Vp.resolveRequestUri(walletConfig, authorizationRequestUri) 

```






## Assumptions

Library focuses on the same device scenario as described in ISO-23220-4 (Appendix B)

It can be assumed that the `AuthorizationRequest` contains a `response_mode`
equal to `direct_post.jwt`

## Supported `response_mode`

A Wallet can take the form a web or mobile application.
Protocol describes flows for both. Given that we are focusing on a mobile wallet we could
assume that `AuthorizationRequest` contains always a `response_mode` equal to `direct_post`

In scope: `direct_post`

Out of scope: `direct_post.jwt`, `redirect`

## Supported Client ID Scheme

Wallet should require the presence of `client_id_scheme` with value
`pre-registered` assuming out of bound knowledge of verifier meta-data

In scope: `pre_registred` , `redirect_uri`

Out of scope: `did`, `entity_id`

## Authorization Request encoding

OAUTH2 foresees that `AuthorizationRequest` is encoded as a HTTP GET
request which contains specific HTTP parameters.

OpenID4VP on the other hand foresees in addition, support to
[RFC 9101](https://www.rfc-editor.org/rfc/rfc9101.html#request_object) where
the aforementioned HTTP Get contains a JWT encoded `AuthorizationRequest`

This is mandatory when supporting `client_id_scheme` equal to `did`.

Out of scope: RFC9101, for JWT-Secured Authorization Requests (JAR)


## Supported response types

Wallet may support several response types. A first release of the SDK
can focus on the `vp_token` response type, which means that the `vp_token`
that satisfies the `PresentationDefinition` (part of the `AuthorizationRequest`)
will be returned with the `AuthorizationResponse`

In scope: `vp_token`
Out of scope: `vp_token id_token`, `id_token`, `code`
