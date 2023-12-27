# EUDI SIOPv2 OpenId4VP library

:heavy_exclamation_mark: **Important!** Before you proceed, please read
the [EUDI Wallet Reference Implementation project description](https://github.com/eu-digital-identity-wallet/.github-private/blob/main/profile/reference-implementation.md)

[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://www.apache.org/licenses/LICENSE-2.0)

## Table of contents

* [Overview](#overview)
* [Disclaimer](#disclaimer)
* [How to use](#how-to-use)
  * [Resolve an authorization request URI](#resolve-an-authorization-request-uri)
  * [Holder's consensus, Handling of a valid authorization request](#holders-consensus-handling-of-a-valid-authorization-request)
  * [Build an authorization response](#build-an-authorization-response)
  * [Dispatch authorization response to verifier / RP](#dispatch-authorization-response-to-verifier--rp)
  * [Example](#example)
* [SIOPv2 & OpenId4VP features supported](#siopv2--openid4vp-features-supported)
* [How to contribute](#how-to-contribute)
* [License](#license)


## Overview

This is a Kotlin library, targeting JVM, that supports 
the [SIOPv2 (draft 12)](https://openid.bitbucket.io/connect/openid-connect-self-issued-v2-1_0.html) 
and [OpenId4VP (draft 19)](https://openid.net/specs/openid-4-verifiable-presentations-1_0.html) protocols.
In particular, the library focus on the wallet's role using those two protocols with constraints
included in ISO 23220-4 and ISO-18013-7


## Disclaimer

The released software is a initial development release version: 
-  The initial development release is an early endeavor reflecting the efforts of a short time-boxed period, and by no means can be considered as the final product.  
-  The initial development release may be changed substantially over time, might introduce new features but also may change or remove existing ones, potentially breaking compatibility with your existing code.
-  The initial development release is limited in functional scope.
-  The initial development release may contain errors or design flaws and other problems that could cause system or other failures and data loss.
-  The initial development release has reduced security, privacy, availability, and reliability standards relative to future releases. This could make the software slower, less reliable, or more vulnerable to attacks than mature software.
-  The initial development release is not yet comprehensively documented. 
-  Users of the software must perform sufficient engineering and additional testing to properly evaluate their application and determine whether any of the open-sourced components is suitable for use in that application.
-  We strongly recommend not putting this version of the software into production use.
-  Only the latest version of the software will be supported

## How to use

```kotlin
// Include library in dependencies in build.gradle.kts
dependencies {
    implementation("eu.europa.ec.euidw:eudi-lib-jvm-siop-openid4vp-kt:$version")
}
```

Entry point to the library is the interface [SiopOpenId4Vp](src/main/kotlin/eu/europa/ec/eudi/openid4vp/SiopOpenId4Vp.kt)
Currently, the library offers an implementation of this interface based on [Ktor](https://ktor.io/) Http Client.
Ktor is built from the ground up using Kotlin and Coroutines.

An instance of the interface can be obtained with the following code

```kotlin
import eu.europa.ec.eudi.openid4vp.*

val walletConfig: SiopOpenId4VPConfig = SiopOpenId4VPConfig(
)

val siopOpenId4Vp = SiopOpenId4Vp.ktor(walletConfig)
```

### Resolve an authorization request URI

Wallet receives an OAUTH2 Authorization request, formed by the Verifier, that may represent 

- a [SIOPv2 authentication request](https://openid.bitbucket.io/connect/openid-connect-self-issued-v2-1_0.html#name-self-issued-openid-provider-a), or
- a [OpenID4VP authorization request](https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#name-authorization-request) or,
- a combined [SIOP & OpenID4VP request](https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#name-combining-this-specificatio)

In the same device scenario, the aforementioned authorization request reaches the wallet in terms of
a deep link. Similarly, in the cross-device scenario, the request would be obtained via scanning a QR Code.

Regardless of the scenario, wallet must take the URI (of the deep link or the QR Code) that represents the
authorization request and ask the SDK to validate the URI (that is to make sure that it represents one of the supported
requests mentioned aforementioned) and in addition gather from Verifier additional information that may be included by
reference (such as `presentation_definition_uri`, `client_metadata_uri` etc)

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

After receiving a valid authorization, the wallet has to process it. Depending on the type of request this means

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
actual HTTP call against the verifier's receiving end-point. On the other hand, in case of a `response_mode`
which is neither `direct_post` nor `direct_post.jwt` the library just forms an appropriate redirect URI. It is the 
caller's responsibility to redirect the user to this URI.

```kotlin
val requestObject // calculated in previous step
val idToken : Jwt // provided by wallet
val consensus =  Consensus.PositiveConsensus.IdTokenConsensus(idToken)
val dispatchOutcome = siopOpenId4Vp.dispatch(requestObject, consensus)
```
### Example
  
Project contains an [example](src/test/kotlin/eu/europa/ec/eudi/openid4vp/Example.kt) which
demonstrates the functionality of the library and in particular the interaction of a
`Verifier` and a `Wallet` via Verifier's trusted end-point to perform an SIOP Authentication.

To run the example you will need to clone [Verifier's trusted end-point](https://github.com/eu-digital-identity-wallet/eudi-srv-web-verifier-endpoint-23220-4-kt)
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


### Supported Client ID Scheme

Library requires the presence of `client_id_scheme` with one of the following values:
 
- `pre-registered` assuming out of bound knowledge of verifier meta-data. A verifier may send an authorization request signed (JAR) or plain
- `x509-san-dns` where verifier must send the authorization request signed (JAR) using by a suitable X509 certificate
- `x509-san-uri` where verifier must send the authorization request signed (JAR) using by a suitable X509 certificate
- `redirect_uri` where verifier must send the authorization request in plain (JAR cannot be used)
- 
### Authorization Request encoding

OAUTH2 foresees that `AuthorizationRequest` is encoded as an HTTP GET
request which contains specific HTTP parameters.

OpenID4VP on the other hand, foresees in addition, support to
[RFC 9101](https://www.rfc-editor.org/rfc/rfc9101.html#request_object) where
the aforementioned HTTP Get contains a JWT encoded `AuthorizationRequest`

Finally, ISO-23220-4 requires the usage of RFC 9101

Library supports obtaining the request object both by value (using `request` attribute) or
by reference (using `request_uri`)


### Presentation Definition
The Verifier articulated requirements of the Credential(s) that are requested using
`presentation_definition` and `presentation_definition_uri` parameters that contain a
Presentation Definition JSON object.

According to OpenId4VP, verifier may pass the `presentation_definition` either

* [by value](https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-5.1)
* [by reference](https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#name-presentation_definition_uri)
* [using scope](https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#name-using-scope-parameter-to-re)

Library supports all these options

### Client metadata in Authorization Request
According to [OpenId4VP](https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#name-authorization-request) verifier may pass his metadata (client metadata) either
* by value, or
* by reference

Library supports both options

### Supported response types

Library currently supports `response_type` equal to `id_token`, `vp_token` or `vp_token id_token`


## How to contribute

We welcome contributions to this project. To ensure that the process is smooth for everyone
involved, follow the guidelines found in [CONTRIBUTING.md](CONTRIBUTING.md).

## License

### Third-party component licenses

* Presentation Exchange v2 [eudi-lib-jvm-presentation-exchange-kt](https://github.com/eu-digital-identity-wallet/eudi-lib-jvm-presentation-exchange-kt)
* OAUTH2 & OIDC Support: [Nimbus OAuth 2.0 SDK with OpenID Connect extensions](https://connect2id.com/products/nimbus-oauth-openid-connect-sdk)
* URI parsing: [Uri KMP](https://github.com/eygraber/uri-kmp)
* Http Client: [Ktor](https://ktor.io/)
* Json : [Kotlinx Serialization](https://github.com/Kotlin/kotlinx.serialization)

### License details

Copyright (c) 2023 European Commission

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
