# SIOPv2 OpenID4VP 

This is a Kotlin library, targeting JVM, that supports the 
[SIOPv2 (draft 12)](https://openid.bitbucket.io/connect/openid-connect-self-issued-v2-1_0.html) and 
[OpenId4VP (draft 18)](https://openid.net/specs/openid-4-verifiable-presentations-1_0.html) protocols.
In particular, the library focus on the wallet's role and in addition focuses on the 
usage of those two protocols as they are constraint by ISO 23220-4 and ISO-18013-7

## Usage

Entry point to the library is interface [SiopOpenId4Vp](src/main/kotlin/eu/europa/ec/euidw/openid4vp/SiopOpenId4Vp.kt)
Currently, the library offers an implementation of this interface based on [Ktor](https://ktor.io/) Http Client.

An instance of the interface can be obtained with the following code

```kotlin
// Include library in dependencies in build.gradle.kts
dependencies {
    api("eu.europa.ec.euidw:eudi-lib-jvm-siop-openid4vp-kt:$version")
}
```

```kotlin
import eu.europa.ec.eudi.openid4vp.*

val walletConfig: WalletOpenId4VPConfig // Provided by wallet
val siopOpenId4Vp = SiopOpenId4Vp.ktor(walletConfig)
```


### Resolve an authorization request URI 

Wallet receives an OAUTH2 Authorization request, formed by the Verifier, that may represent either 

- a [SIOPv2 authentication request](https://openid.bitbucket.io/connect/openid-connect-self-issued-v2-1_0.html#name-self-issued-openid-provider-a), or 
- a [OpenID4VP authorization request](https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#name-authorization-request),  
- or a combined [SIOP & OpenID4VP request](https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#name-combining-this-specificatio)

In the same device  scenario the aforementioned authorization request reaches the wallet in terms of 
a deep link. Similarly, in the cross device scenario, the request would be obtained via scanning a QR Code.

Regardless of the scenario, wallet must take the URI (of the deep link or the QR Code) that represents the 
authorization request and ask the SDK to validate the URI (that is to make sure that it represents one of the supported
requests mentioned aforementioned) and in addition gather from Verifier additional information that may be included by
reference (such as `presentation_definition_uri`, `client_metadata_uri` etc)

The interface that captures the aforementioned functionality is 
[AuthorizationRequestResolver](src/main/kotlin/eu/europa/ec/euidw/openid4vp/AuthorizationRequestResolver.kt)

```kotlin
import eu.europa.ec.eudi.openid4vp.*

val authorizationRequestUri : String // obtained via deep link or scanning a QR code

val resolution = siopOpenId4Vp.resolveRequestUri(walletConfig, authorizationRequestUri)
val requestObject = when (resolution) {
    is Resolution.Invalid -> throw resolution.error.asException()
    is Resolution.Success -> resolution.requestObject
}

```

### Holder's consensus, Handling of a valid authorization request

After receiving a valid authorization wallet has to process it. Depending on the type of request this means

* For a SIOPv2 authentication request, wallet must get holder's consensus and provide an `id_token`
* For a OpenID4VP authorization request, 
  * wallet should check whether holder has claims that can fulfill verifier's requirements
  * let the holder choose which claims will be presented to the verifier and form a `vp_token`
* For a combined SIOP & OpenID4VP request, wallet should perform both actions described above.

This functionality is a wallet concern and it is not supported directly by the library 

### Build an authorization response

After collecting holder's consensus, wallet can use the library to form an appropriate response.
The interface that captures the aforementioned functionality is
[AuthorizationResponseBuilder](src/main/kotlin/eu/europa/ec/euidw/openid4vp/AuthorizationResponseBuilder.kt)

```kotlin
import eu.europa.ec.eudi.openid4vp.*
// Example assumes that requestObject is SiopAuthentication & holder's agreed to the issuance of id_token
val requestObject // calculated in previous step
val idToken : Jwt // provided by wallet
val consensus =  Consensus.PositiveConsensus.IdTokenConsensus(idToken)
val authorizationResponse = siopOpenId4Vp.build(requestObject, consensus)
```

### Dispatch authorization response to verifier / RP

The final step, of processing an authorization request, is to dispatch to the verifier the authorization response.
Depending on the `response_mode` that the verifier included in his authorization request, this is done either 
* via a direct post (when `response_mode` is `direct_post` or `direct_post.jwt`), or
* by forming an appropriate `redirect_uri` (when response mode is `fragment` or `fragment.jwt`)

Library tackles this dispatching via [Dispatcher](src/main/kotlin/eu/europa/ec/euidw/openid4vp/Dispatcher.kt)

```kotlin
val authorizationResponse // from previous step
val dispatchOutcome = siopOpenId4Vp.dispatch(authorizationResponse)
```

## SIOPv2 & OpenId4VP features supported

## `response_mode`

A Wallet can take the form a web or mobile application.
OpenId4VP describes flows for both cases. Given that we are focusing on a mobile wallet we could
assume that `AuthorizationRequest` contains always a `response_mode` equal to `direct_post`

Library currently supports `response_mode` 
* `direct_post`
* `redirect` (fragment or query)


## Supported Client ID Scheme

Library requires the presence of `client_id_scheme` with value
`pre-registered` assuming out of bound knowledge of verifier meta-data

## Authorization Request encoding

OAUTH2 foresees that `AuthorizationRequest` is encoded as an HTTP GET
request which contains specific HTTP parameters.

OpenID4VP on the other hand foresees in addition, support to
[RFC 9101](https://www.rfc-editor.org/rfc/rfc9101.html#request_object) where
the aforementioned HTTP Get contains a JWT encoded `AuthorizationRequest`

Finally, ISO-23220-4 requires the  usage of RFC 9101

Library supports obtaining the request object both by value (using `request` attribute) or
by reference (using `request_uri`)


## Presentation Definition

According to OpenId4VP, verifier may pass the `presentation_definition` either

* [by value](https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-5.1)
* [by reference](https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#name-presentation_definition_uri)
* [using scope](https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#name-using-scope-parameter-to-re)

Library supports all these options

## Client metadata in Authorization Request
According to [OpenId4VP](https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#name-authorization-request) verifier may pass his metadata (client metadata) either 
* by value, or
* by reference

Library supports both options

## Supported response types

Library currently supports `response_type` equal to `id_token` or `vp_token id_token`


## Dependencies (to other libs)

* Presentation Exchange v2 [eudi-lib-jvm-presentation-exchange-kt](https://github.com/eu-digital-identity-wallet/eudi-lib-jvm-presentation-exchange-kt)
* OAUTH2 & OIDC Support: [Nimbus OAuth 2.0 SDK with OpenID Connect extensions](https://connect2id.com/products/nimbus-oauth-openid-connect-sdk)
* URI parsing: [Uri KMP](https://github.com/eygraber/uri-kmp)
* Http Client: [Ktor](https://ktor.io/)
* Json : [Kotlinx Serialization](https://github.com/Kotlin/kotlinx.serialization)