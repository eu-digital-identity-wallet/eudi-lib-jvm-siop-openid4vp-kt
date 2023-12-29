/*
 * Copyright (c) 2023 European Commission
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package eu.europa.ec.eudi.openid4vp.internal.request

import com.nimbusds.jose.JOSEException
import com.nimbusds.jose.JOSEObjectType
import com.nimbusds.jose.jwk.JWKSet
import com.nimbusds.jose.jwk.source.ImmutableJWKSet
import com.nimbusds.jose.jwk.source.JWKSource
import com.nimbusds.jose.proc.*
import com.nimbusds.jose.shaded.gson.Gson
import com.nimbusds.jose.util.X509CertUtils
import com.nimbusds.jwt.JWTClaimsSet
import com.nimbusds.jwt.SignedJWT
import com.nimbusds.jwt.proc.DefaultJWTProcessor
import eu.europa.ec.eudi.openid4vp.*
import eu.europa.ec.eudi.openid4vp.SupportedClientIdScheme.Preregistered
import eu.europa.ec.eudi.openid4vp.internal.ensure
import eu.europa.ec.eudi.openid4vp.internal.ensureNotNull
import eu.europa.ec.eudi.openid4vp.internal.sanOfDNSName
import eu.europa.ec.eudi.openid4vp.internal.sanOfUniformResourceIdentifier
import io.ktor.client.*
import io.ktor.client.call.*
import io.ktor.client.request.*
import io.ktor.http.*
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.jsonObject
import java.net.URI
import java.security.cert.X509Certificate
import java.text.ParseException

internal sealed interface AuthenticatedClient {
    data class Preregistered(val preregisteredClient: PreregisteredClient) : AuthenticatedClient
    data class RedirectUri(val clientId: URI) : AuthenticatedClient
    data class X509SanDns(val clientId: String, val chain: List<X509Certificate>) : AuthenticatedClient
    data class X509SanUri(val clientId: URI, val chain: List<X509Certificate>) : AuthenticatedClient
}

internal data class AuthenticatedRequest(
    val client: AuthenticatedClient,
    val requestObject: UnvalidatedRequestObject,
)

internal class RequestAuthenticator private constructor(
    private val clientAuthenticator: ClientAuthenticator,
    private val jarJwtValidator: JarJwtSignatureValidator,
) {

    constructor(
        siopOpenId4VPConfig: SiopOpenId4VPConfig,
        httpClientFactory: KtorHttpClientFactory,
    ) : this(
        ClientAuthenticator(siopOpenId4VPConfig),
        JarJwtSignatureValidator(siopOpenId4VPConfig, httpClientFactory),
    )

    suspend fun authenticate(request: FetchedRequest<Jwt>): AuthenticatedRequest = when (request) {
        is FetchedRequest.Plain -> authenticatePlain(request)
        is FetchedRequest.JwtSecured -> authenticateJwtSecured(request)
    }

    private fun authenticatePlain(request: FetchedRequest.Plain): AuthenticatedRequest {
        val client = clientAuthenticator.authenticateClient(request)
        return AuthenticatedRequest(client, request.requestObject)
    }
    private suspend fun authenticateJwtSecured(request: FetchedRequest.JwtSecured<Jwt>): AuthenticatedRequest {
        val signedJwt = request.jwt.parseJwt()
        val client = clientAuthenticator.authenticateClient(FetchedRequest.JwtSecured(request.clientId, signedJwt))
        val requestObject = signedJwt.jwtClaimsSet.toType { requestObject(it) }
        ensure(request.clientId == requestObject.clientId) {
            invalidJarJwt("ClientId mismatch. JAR request ${request.clientId}, jwt ${request.clientId}")
        }
        jarJwtValidator.validate(client, signedJwt)
        return AuthenticatedRequest(client, requestObject)
    }
}

private class ClientAuthenticator(private val siopOpenId4VPConfig: SiopOpenId4VPConfig) {
    fun authenticateClient(request: FetchedRequest<SignedJWT>): AuthenticatedClient {
        val requestObject = when (request) {
            is FetchedRequest.JwtSecured -> request.jwt.jwtClaimsSet.toType { requestObject(it) }
            is FetchedRequest.Plain -> request.requestObject
        }

        val (clientId, clientIdScheme) = clientIdAndScheme(requestObject)
        return when (clientIdScheme) {
            is Preregistered -> {
                val registeredClient = clientIdScheme.clients[clientId]
                ensureNotNull(registeredClient) { RequestValidationError.InvalidClientId.asException() }
                if (request is FetchedRequest.JwtSecured) {
                    ensureNotNull(registeredClient.jarConfig) {
                        invalidScheme("$registeredClient cannot place signed request")
                    }
                }
                AuthenticatedClient.Preregistered(registeredClient)
            }

            SupportedClientIdScheme.RedirectUri -> {
                ensure(request is FetchedRequest.Plain) { invalidScheme("$clientIdScheme cannot be used in signed request") }
                val clientIdUri = clientId.asURI { RequestValidationError.InvalidClientId.asException() }.getOrThrow()
                AuthenticatedClient.RedirectUri(clientIdUri)
            }

            is SupportedClientIdScheme.X509SanDns -> {
                ensure(request is FetchedRequest.JwtSecured) { invalidScheme("$clientIdScheme cannot be used in unsigned request") }
                val chain = x5c(request, clientIdScheme.trust, X509Certificate::sanOfDNSName)
                AuthenticatedClient.X509SanDns(request.clientId, chain)
            }

            is SupportedClientIdScheme.X509SanUri -> {
                ensure(request is FetchedRequest.JwtSecured) { invalidScheme("$clientIdScheme cannot be used in unsigned request") }
                val chain = x5c(request, clientIdScheme.trust, X509Certificate::sanOfUniformResourceIdentifier)
                val clientIdUri = clientId.asURI { RequestValidationError.InvalidClientId.asException() }.getOrThrow()
                AuthenticatedClient.X509SanUri(clientIdUri, chain)
            }
        }
    }

    private fun clientIdAndScheme(requestObject: UnvalidatedRequestObject): Pair<String, SupportedClientIdScheme> {
        val clientId = ensureNotNull(requestObject.clientId) { RequestValidationError.MissingClientId.asException() }
        val clientIdScheme = requestObject.clientIdScheme?.let { ClientIdScheme.make(it) }
        ensureNotNull(clientIdScheme) { invalidScheme("Missing or invalid client_id_scheme") }
        val supportedClientIdScheme = siopOpenId4VPConfig.supportedClientIdScheme(clientIdScheme)
        ensureNotNull(supportedClientIdScheme) { RequestValidationError.UnsupportedClientIdScheme.asException() }
        return clientId to supportedClientIdScheme
    }

    private fun x5c(
        request: FetchedRequest.JwtSecured<SignedJWT>,
        trust: X509CertificateTrust,
        subjectAlternativeNames: X509Certificate.() -> Result<List<String>>,
    ): List<X509Certificate> {
        val pubCertChain = request.jwt.header
            ?.x509CertChain
            ?.mapNotNull { X509CertUtils.parse(it.decode()) }
        ensureNotNull(pubCertChain) { invalidJarJwt("Missing or invalid x5c") }

        val cert = pubCertChain[0]
        val sans = cert.subjectAlternativeNames().getOrElse {
            throw invalidJarJwt("x5c misses Subject Alternative Names of type UniformResourceIdentifier")
        }
        if (!sans.contains(request.clientId)) throw invalidJarJwt("ClientId not found in x5c Subject Alternative Names")
        if (!trust.isTrusted(pubCertChain)) throw invalidJarJwt("Untrusted x5c")
        return pubCertChain
    }
}

/**
 * Validates a JWT that represents an Authorization Request according to RFC9101
 *
 * @param siopOpenId4VPConfig wallet's configuration
 * @param httpClientFactory a factory to obtain a Ktor http client
 */
private class JarJwtSignatureValidator(
    private val siopOpenId4VPConfig: SiopOpenId4VPConfig,
    private val httpClientFactory: KtorHttpClientFactory,
) {

    @Throws(AuthorizationRequestException::class)
    suspend fun validate(client: AuthenticatedClient, signedJwt: SignedJWT) {
        try {
            val jwtProcessor = DefaultJWTProcessor<SecurityContext>().apply {
                jwsTypeVerifier = DefaultJOSEObjectTypeVerifier(JOSEObjectType("oauth-authz-req+jwt"))
                jwsKeySelector = jwsKeySelector(client)
            }
            jwtProcessor.process(signedJwt, null)
        } catch (e: JOSEException) {
            throw RuntimeException(e)
        } catch (e: BadJOSEException) {
            throw invalidJarJwt("Invalid signature ${e.message}")
        }
    }

    @Throws(AuthorizationRequestException::class)
    private suspend fun jwsKeySelector(client: AuthenticatedClient): JWSKeySelector<SecurityContext> =
        when (client) {
            is AuthenticatedClient.Preregistered -> getPreRegisteredClientJwsSelector(client)
            is AuthenticatedClient.X509SanUri -> JWSKeySelector<SecurityContext> { _, _ -> listOf(client.chain[0].publicKey) }
            is AuthenticatedClient.X509SanDns ->
                JWSKeySelector<SecurityContext> { _, _ -> listOf(client.chain[0].publicKey) }

            is AuthenticatedClient.RedirectUri -> throw RequestValidationError.UnsupportedClientIdScheme.asException()
        }

    @Throws(AuthorizationRequestException::class)
    private suspend fun getPreRegisteredClientJwsSelector(
        preregistered: AuthenticatedClient.Preregistered,
    ): JWSVerificationKeySelector<SecurityContext> {
        val trustedClient = preregistered.preregisteredClient
        val jarConfig = checkNotNull(trustedClient.jarConfig)

        val (jarSigningAlg, jwkSetSource) = jarConfig
        suspend fun getJWKSource(): JWKSource<SecurityContext> {
            val jwkSet = when (jwkSetSource) {
                is JwkSetSource.ByValue -> JWKSet.parse(jwkSetSource.jwks.toString())
                is JwkSetSource.ByReference ->
                    httpClientFactory().use { client ->
                        val unparsed = client.get(jwkSetSource.jwksUri.toURL()).body<String>()
                        JWKSet.parse(unparsed)
                    }
            }
            return ImmutableJWKSet(jwkSet)
        }

        val jwkSource = getJWKSource()
        return JWSVerificationKeySelector(jarSigningAlg, jwkSource)
    }
}

private fun invalidScheme(cause: String): AuthorizationRequestException =
    RequestValidationError.InvalidClientIdScheme(cause).asException()

private fun invalidJarJwt(cause: String): AuthorizationRequestException =
    RequestValidationError.InvalidJarJwt(cause).asException()

private fun String.parseJwt(): SignedJWT = try {
    SignedJWT.parse(this)
} catch (pe: ParseException) {
    throw invalidJarJwt("JAR JWT parse error")
}

private fun requestObject(cs: JWTClaimsSet): UnvalidatedRequestObject {
    fun Map<String, Any?>.asJsonObject(): JsonObject {
        val jsonStr = Gson().toJson(this)
        return Json.parseToJsonElement(jsonStr).jsonObject
    }

    return with(cs) {
        UnvalidatedRequestObject(
            responseType = getStringClaim("response_type"),
            presentationDefinition = getJSONObjectClaim("presentation_definition")?.asJsonObject(),
            presentationDefinitionUri = getStringClaim("presentation_definition_uri"),
            scope = getStringClaim("scope"),
            nonce = getStringClaim("nonce"),
            responseMode = getStringClaim("response_mode"),
            clientIdScheme = getStringClaim("client_id_scheme"),
            clientMetaData = getJSONObjectClaim("client_metadata")?.asJsonObject(),
            clientMetadataUri = getStringClaim("client_metadata_uri"),
            clientId = getStringClaim("client_id"),
            responseUri = getStringClaim("response_uri"),
            redirectUri = getStringClaim("redirect_uri"),
            state = getStringClaim("state"),
            supportedAlgorithm = getStringClaim("supported_algorithm"),
            idTokenType = getStringClaim("id_token_type"),
        )
    }
}
