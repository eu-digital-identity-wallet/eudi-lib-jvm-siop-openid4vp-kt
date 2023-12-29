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
import eu.europa.ec.eudi.openid4vp.internal.sanOfDNSName
import eu.europa.ec.eudi.openid4vp.internal.sanOfUniformResourceIdentifier
import io.ktor.client.*
import io.ktor.client.call.*
import io.ktor.client.request.*
import io.ktor.http.*
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.jsonObject
import java.security.cert.X509Certificate
import java.text.ParseException

internal data class AuthenticatedRequestObject(
    val clientIdScheme: SupportedClientIdScheme,
    val requestObject: UnvalidatedRequestObject,
)

internal class RequestAuthenticator(
    private val siopOpenId4VPConfig: SiopOpenId4VPConfig,
    private val httpClientFactory: KtorHttpClientFactory,
) {

    private val jarJwtValidator = JarJwtSignatureValidator(siopOpenId4VPConfig, httpClientFactory)

    suspend fun fetchAndAuthenticate(request: UnvalidatedRequest): AuthenticatedRequestObject =
        when (request) {
            is UnvalidatedRequest.Plain -> authenticate(request)
            is UnvalidatedRequest.JwtSecured -> authenticate(request)
        }
    private fun authenticate(request: UnvalidatedRequest.Plain): AuthenticatedRequestObject {
        val requestObject = request.requestObject
        fun invalidScheme() = RequestValidationError.InvalidClientIdScheme(requestObject.clientIdScheme.orEmpty()).asException()
        val clientIdScheme = requestObject.clientIdScheme?.let {
            ClientIdScheme.make(it)?.takeIf(ClientIdScheme::supportsNonJar)
        } ?: throw invalidScheme()

        fun knownClient(s: SupportedClientIdScheme) =
            if (s !is Preregistered) true
            else s.clients.containsKey(requestObject.clientId)

        val supportedClientIdScheme = siopOpenId4VPConfig.supportedClientIdScheme(clientIdScheme)
        val auth = supportedClientIdScheme
            ?.takeIf(::knownClient)
            ?: throw RequestValidationError.UnsupportedClientIdScheme.asException()
        return AuthenticatedRequestObject(auth, requestObject)
    }

    private suspend fun authenticate(request: UnvalidatedRequest.JwtSecured): AuthenticatedRequestObject {
        suspend fun fetchJwt(request: UnvalidatedRequest.JwtSecured.PassByReference): Jwt =
            httpClientFactory().use { client ->
                client.get(request.jwtURI) {
                    accept(ContentType.parse("application/oauth-authz-req+jwt"))
                }.body<String>()
            }

        val unvalidatedJwt: Jwt = when (request) {
            is UnvalidatedRequest.JwtSecured.PassByValue -> request.jwt
            is UnvalidatedRequest.JwtSecured.PassByReference -> fetchJwt(request)
        }

        val (clientIdScheme, requestObject) = jarJwtValidator.validate(request.clientId, unvalidatedJwt)
        return AuthenticatedRequestObject(clientIdScheme, requestObject)
    }
}

private val OnlyNonJar = listOf(ClientIdScheme.RedirectUri)
private val OnlyJar = listOf(ClientIdScheme.X509_SAN_DNS, ClientIdScheme.X509_SAN_URI, ClientIdScheme.DID)
private val EitherJarOrNoJar = listOf(ClientIdScheme.PreRegistered, ClientIdScheme.EntityId)

private fun ClientIdScheme.supportsNonJar() = this in OnlyNonJar || this in EitherJarOrNoJar
private fun ClientIdScheme.supportsJar() = this in OnlyJar || this in EitherJarOrNoJar

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
    suspend fun validate(clientId: String, unverifiedJwt: Jwt): Pair<SupportedClientIdScheme, UnvalidatedRequestObject> {
        val signedJwt = parse(unverifiedJwt)
        val supportedClientIdScheme = validateSignatureForClientIdScheme(clientId, signedJwt)
        val requestObject = signedJwt.jwtClaimsSet.toType { requestObject(it) }
        return supportedClientIdScheme to requestObject
    }

    /**
     * Parses the given [unverifiedJwt] to verify that has the form
     * of a [SignedJWT]. It doesn't perform signature validation
     *
     * @param unverifiedJwt The JWT to parse
     * @return the parsed JWT
     * @throws AuthorizationRequestException in case the [unverifiedJwt] is not compliant with the JWT format
     */
    @Throws(AuthorizationRequestException::class)
    private fun parse(unverifiedJwt: Jwt): SignedJWT =
        try {
            SignedJWT.parse(unverifiedJwt)
        } catch (pe: ParseException) {
            throw invalidJarJwt("JAR JWT parse error")
        }

    @Throws(AuthorizationRequestException::class)
    private suspend fun validateSignatureForClientIdScheme(
        clientId: String,
        signedJwt: SignedJWT,
    ): SupportedClientIdScheme {
        val untrustedClaimSet = signedJwt.jwtClaimsSet
        val jwtClientId = untrustedClaimSet.getStringClaim("client_id")
        val supportedClientIdScheme =
            untrustedClaimSet.getStringClaim("client_id_scheme")
                ?.let { ClientIdScheme.make(it)?.takeIf { x -> x.supportsJar() } }
                ?.let { siopOpenId4VPConfig.supportedClientIdScheme(it) }

        fun clientIdMismatch() = invalidJarJwt("ClientId mismatch. JAR request $clientId, jwt $jwtClientId")

        return when {
            null == jwtClientId -> throw RequestValidationError.MissingClientId.asException()
            clientId != jwtClientId -> throw clientIdMismatch()
            else -> {
                val keySelector = jwsKeySelector(clientId, supportedClientIdScheme, signedJwt)
                signedJwt.verifySignature { keySelector }
                checkNotNull(supportedClientIdScheme)
            }
        }
    }

    @Throws(AuthorizationRequestException::class)
    private suspend fun SignedJWT.verifySignature(
        jwsKetSelector: suspend () -> JWSKeySelector<SecurityContext>,
    ) {
        try {
            val jwtProcessor = DefaultJWTProcessor<SecurityContext>().apply {
                jwsTypeVerifier = DefaultJOSEObjectTypeVerifier(JOSEObjectType("oauth-authz-req+jwt"))
                jwsKeySelector = jwsKetSelector()
            }
            jwtProcessor.process(this, null)
        } catch (e: JOSEException) {
            throw RuntimeException(e)
        } catch (e: BadJOSEException) {
            throw invalidJarJwt("Invalid signature ${e.message}")
        }
    }

    @Throws(AuthorizationRequestException::class)
    private suspend fun jwsKeySelector(
        clientId: String,
        supportedClientIdScheme: SupportedClientIdScheme?,
        signedJwt: SignedJWT,
    ): JWSKeySelector<SecurityContext> = when (supportedClientIdScheme) {
        is Preregistered -> getPreRegisteredClientJwsSelector(clientId, supportedClientIdScheme)
        is SupportedClientIdScheme.X509SanUri ->
            x509SanJwsSelector(
                supportedClientIdScheme.trust,
                clientId,
                signedJwt,
                X509Certificate::sanOfUniformResourceIdentifier,
            )

        is SupportedClientIdScheme.X509SanDns ->
            x509SanJwsSelector(
                supportedClientIdScheme.trust,
                clientId,
                signedJwt,
                X509Certificate::sanOfDNSName,
            )

        null, SupportedClientIdScheme.RedirectUri -> throw RequestValidationError.UnsupportedClientIdScheme.asException()
    }

    @Throws(AuthorizationRequestException::class)
    private suspend fun getPreRegisteredClientJwsSelector(
        clientId: String,
        preregistered: Preregistered,
    ): JWSVerificationKeySelector<SecurityContext> {
        val trustedClient = preregistered.clients[clientId]
        ensure(trustedClient != null) { invalidJarJwt("Verifier with $clientId is not pre-registered") }
        val jarConfig = trustedClient.jarConfig
        ensure(jarConfig != null) { invalidJarJwt("Verifier with $clientId has not been configured for JAR") }
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

@Throws(AuthorizationRequestException::class)
private fun x509SanJwsSelector(
    trust: X509CertificateTrust,
    clientId: String,
    signedJwt: SignedJWT,
    subjectAlternativeNames: X509Certificate.() -> Result<List<String>>,
): JWSKeySelector<SecurityContext> {
    val pubCertChain = signedJwt.header
        ?.x509CertChain
        ?.mapNotNull { X509CertUtils.parse(it.decode()) }
        ?: throw invalidJarJwt("Missing or invalid x5c")

    val cert = pubCertChain[0]
    val sans = cert.subjectAlternativeNames().getOrElse {
        throw invalidJarJwt("x5c misses Subject Alternative Names of type UniformResourceIdentifier")
    }
    if (!sans.contains(clientId)) throw invalidJarJwt("ClientId not found in x5c Subject Alternative Names")
    if (!trust.isTrusted(pubCertChain)) throw invalidJarJwt("Untrusted x5c")

    return JWSKeySelector<SecurityContext> { _, _ -> listOf(cert.publicKey) }
}

private fun invalidJarJwt(cause: String): AuthorizationRequestException =
    RequestValidationError.InvalidJarJwt(cause).asException()

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
