# OpenID4VP first release

## Cross device & Same Device

SDK should be agnostic of this. That's a wallet's concern.
For a simple application (not the wallet) that demonstrates the SDK usage,
we can assume the cross device scenario.

What this means for the SDK?
It can be assumed that the `AuthorizationRequest` contains a `response_mode`
equal to `direct_post`

## Supported `response_mode`

A Wallet can take the form a a web or mobile application.
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

## Supported formats

TBD?

## Supported response types

Wallet may support several response types. A first release of the SDK
can focus on the `vp_token` response type, which means that the `vp_token`
that satisfies the `PresentationDefinition` (part of the `AuthorizationRequest`)
will be returned with the `AuthorizationResponse`

In scope: `vp_token`
Out of scope: `vp_token id_token`, `id_token`, `code`
