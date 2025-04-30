# Module SIOPv2 OpenId4VP

The `eudi-lib-jvm-siop-openid4vp-kt` is a Kotlin library, targeting JVM, that supports
the [SIOPv2 (draft 13)](https://openid.github.io/SIOPv2/openid-connect-self-issued-v2-wg-draft.html)
and [OpenId4VP (draft 24)](https://openid.net/specs/openid-4-verifiable-presentations-1_0-24.html) protocols.
In particular, the library focus on the wallet's role using those two protocols with constraints
included in ISO 23220-4 and ISO-18013-7


## eu.europa.ec.eudi.openid4vp

### Resolve an authorization request URI

Wallet receives an OAUTH2 Authorization request, formed by the Verifier, that may represent

- a [SIOPv2 authentication request](https://openid.github.io/SIOPv2/openid-connect-self-issued-v2-wg-draft.html#name-self-issued-openid-provider-a), or
- a [OpenID4VP authorization request](https://openid.net/specs/openid-4-verifiable-presentations-1_0-24.html#name-authorization-request) or,
- a combined [SIOP & OpenID4VP request](https://openid.net/specs/openid-4-verifiable-presentations-1_0-24.html#name-combining-this-specificatio)

In the same device scenario, the aforementioned authorization request reaches the wallet in terms of a deep link.
Similarly, in the cross-device scenario, the request would be obtained via scanning a QR Code.

Regardless of the scenario, wallet must take the URI (of the deep link or the QR Code) that represents the
authorization request and ask the SDK to validate the URI (that is to make sure that it represents one of the supported
requests mentioned aforementioned) and in addition gather from Verifier additional information that may be included by
reference (such as `presentation_definition_uri`, `client_metadata_uri` etc.)

The interface that captures the aforementioned functionality is
[AuthorizationRequestResolver](src/main/kotlin/eu/europa/ec/eudi/openid4vp/AuthorizationRequestResolver.kt)

```kotlin
import eu.europa.ec.eudi.openid4vp.*

val authorizationRequestUri : String // obtained via a deep link or scanning a QR code

val resolution = siopOpenId4Vp.resolveRequestUri(authorizationRequestUri)
val requestObject = when (resolution) {
    is Resolution.Invalid -> throw resolution.error.asException()
    is Resolution.Success -> resolution.requestObject
}

```
### Holder's consensus, Handling of a valid authorization request

After receiving a valid authorization, the wallet has to process it. Depending on the type of request, this means

* For a SIOPv2 authentication request, wallet must get holder's consensus and provide an `id_token`
* For an OpenID4VP authorization request,
  * wallet should check whether holder has claims that can fulfill verifier's requirements
  * let the holder choose which claims will be presented to the verifier and form a `vp_token`
* For a combined SIOP & OpenID4VP request, wallet should perform both actions described above.

This functionality is a wallet concern, and it is not supported directly by the library

### Dispatch authorization response to verifier / RP

After collecting holder's consensus, wallet can use the library to form an appropriate response and then dispatch it
to the verifier.
Depending on the `response_mode` that the verifier included in his authorization request, this is done via

* either a direct post (when `response_mode` is `direct_post` or `direct_post.jwt`), or
* by forming an appropriate `redirect_uri` (when response mode is `fragment`, `fragment.jwt`, `query` or `query.jwt`)

The library tackles this dispatching via [Dispatcher](src/main/kotlin/eu/europa/ec/eudi/openid4vp/ResponseDispatcher.kt)

Please note that in case of `response_mode` `direct_post` or `direct_post.jwt` the library actually performs the
actual HTTP call against the verifier's receiving end-point.
On the other hand, in case of a `response_mode` which is neither `direct_post` nor `direct_post.jwt` the library 
just forms an appropriate redirect URI.
It is the caller's responsibility to redirect the user to this URI.

```kotlin
val requestObject // calculated in previous step
val idToken : Jwt // provided by wallet
val consensus =  Consensus.PositiveConsensus.IdTokenConsensus(idToken)
val dispatchOutcome = siopOpenId4Vp.dispatch(requestObject, consensus)
```
### Example

Project contains an [example](src/test/kotlin/eu/europa/ec/eudi/openid4vp/Example.kt) which
demonstrates the functionality of the library and in particular the interaction of a
`Verifier` and a `Wallet` via Verifier's trusted end-point to perform an SIOP Authentication, and an OpenId4VP Authorization.

To run the example, you will need to clone [Verifier's trusted end-point](https://github.com/eu-digital-identity-wallet/eudi-srv-web-verifier-endpoint-23220-4-kt)
and run it using

```bash
./gradlew bootRun
```
and then run the Example.


## SIOPv2 & OpenId4VP features supported

### `response_mode`

A Wallet can take the form of a web or mobile application.
OpenId4VP describes flows for both cases. Given that we are focusing on a mobile wallet we could
assume that `AuthorizationRequest` contains always a `response_mode`

Library currently supports `response_mode`
* `direct_post`
* `direct_post.jwt`
* `fragment`
* `fragment.jwt`
* `query`
* `query.jwt`


### Supported Client ID Schemes

Library requires the presence of a `client_id` using one of the following schemes:

- `pre-registered` assuming out of bound knowledge of verifier meta-data. A verifier may send an authorization request signed (JAR) or plain
- `x509_san_dns` where verifier must send the authorization request signed (JAR) using by a suitable X509 certificate
- `x509_san_uri` where verifier must send the authorization request signed (JAR) using by a suitable X509 certificate
- `redirect_uri` where verifier must send the authorization request in plain (JAR cannot be used)
- `did` where verifier must send the authorization request signed (JAR) using a key resolvable via DID URL.
- `verifier_attestation` where verifier must send the authorization request signed (JAR), witch contains a verifier attestation JWT from a trusted issuer

> [!NOTE]
> The Client ID Scheme is encoded as a prefix in `client_id`. Absence of such a prefix, indicates the usage of the `pre-registered` Client ID Scheme.

### Retrieving Authorization Request

According to OpenID4VP, when the `request_uri` parameter is included in the authorization request wallet must fetch the Authorization Request by following this URI.
In this case there are two methods to get the request, controlled by the `request_uri_method` communicated by the verifier:
- Via an HTTP GET: In this case the Wallet MUST send the request to retrieve the Request Object using the HTTP GET method, as defined in [RFC9101](https://www.rfc-editor.org/rfc/rfc9101.html).
- Via an HTTP POST: In this case a supporting Wallet MUST send the request using the HTTP POST method as detailed in [Section 5.11](https://openid.net/specs/openid-4-verifiable-presentations-1_0-24.html#name-request-uri-method-post).

In the later case, based on the configured [SupportedRequestUriMethods](src/main/kotlin/eu/europa/ec/eudi/openid4vp/Config.kt), Wallet can communicate to the Verifier:
- A Nonce value to be included in the JWT-Secured Authorization Request (via `wallet_nonce` parameter)
- Its [metadata](src/main/kotlin/eu/europa/ec/eudi/openid4vp/internal/request/WalletMetaData.kt)  (via `wallet_metadata` parameter)

Library supports both methods.

> [!NOTE]
> Library currently does not support encrypted JWT-Secured Authorization Requests.

### Authorization Request encoding

OAUTH2 foresees that `AuthorizationRequest` is encoded as an HTTP GET request which contains specific HTTP parameters.

OpenID4VP on the other hand, foresees in addition, support to
[RFC 9101](https://www.rfc-editor.org/rfc/rfc9101.html#request_object) where
the aforementioned HTTP Get contains a JWT encoded `AuthorizationRequest`

Finally, ISO-23220-4 requires the usage of RFC 9101

Library supports obtaining the request object both by value (using `request` attribute) or
by reference (using `request_uri`)

### Verifiable Credentials Requirements

As per OpenId4VP, the Verifier can describe the requirements of the Verifiable Credential(s) to be presented using:

* [Presentation Exchange 2.0.0](https://identity.foundation/presentation-exchange/spec/v2.0.0/)
* [Digital Credentials Query Language (DCQL)](https://openid.net/specs/openid-4-verifiable-presentations-1_0-24.html#name-digital-credentials-query-l)

**Presentation Exchange 2.0.0**:

The Verifier articulated requirements of the Verifiable Credential(s) that are requested, are provided using
`presentation_definition` and `presentation_definition_uri` parameters that contain a Presentation Definition JSON object.

According to OpenId4VP, verifier may pass the `presentation_definition` either

* [by value](https://openid.net/specs/openid-4-verifiable-presentations-1_0-24.html#section-5.4)
* [by reference](https://openid.net/specs/openid-4-verifiable-presentations-1_0-24.html#section-5.5)
* [using scope](https://openid.net/specs/openid-4-verifiable-presentations-1_0-24.html#section-5.6)

Library supports all these options

**DCQL**:

The Verifier articulated requirements of the Verifiable Credential(s) that are requested, are provided using
the `dcql_query` parameter that contains a [DCQL Query](https://openid.net/specs/openid-4-verifiable-presentations-1_0-24.html#section-6-2) JSON object.

According to OpenId4VP, verifier may pass the `dcql_query` either

* [by value](https://openid.net/specs/openid-4-verifiable-presentations-1_0-24.html#section-5.1-2.6)
* [using scope](https://openid.net/specs/openid-4-verifiable-presentations-1_0-24.html#section-5.6)

Library supports all these options

> [!NOTE]
> Passing a DCQL Query by reference is not supported by OpenId4VP.

> [!IMPORTANT]  
> When scope is used, library tries to match it first to a well known Presentation Definition, and then to a well known DCQL query. 

### Client metadata in Authorization Request

According to [OpenId4VP](https://openid.net/specs/openid-4-verifiable-presentations-1_0-24.html#name-authorization-request) verifier may pass his metadata (client metadata) either
* by value, or
* by reference

Library supports both options

### Supported response types

Library currently supports `response_type` equal to `id_token`, `vp_token` or `vp_token id_token`
