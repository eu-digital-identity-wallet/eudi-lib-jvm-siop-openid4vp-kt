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
import com.nimbusds.jose.jwk.AsymmetricJWK
import com.nimbusds.jose.jwk.JWK
import com.nimbusds.jose.jwk.JWKSet
import com.nimbusds.jose.jwk.source.ImmutableJWKSet
import com.nimbusds.jose.jwk.source.JWKSource
import com.nimbusds.jose.proc.*
import com.nimbusds.jose.shaded.gson.Gson
import com.nimbusds.jose.util.X509CertUtils
import com.nimbusds.jwt.JWTClaimsSet
import com.nimbusds.jwt.SignedJWT
import com.nimbusds.jwt.proc.BadJWTException
import com.nimbusds.jwt.proc.DefaultJWTProcessor
import com.nimbusds.jwt.proc.JWTClaimsSetVerifier
import com.nimbusds.jwt.util.DateUtils
import eu.europa.ec.eudi.openid4vp.*
import eu.europa.ec.eudi.openid4vp.SupportedClientIdScheme.Preregistered
import eu.europa.ec.eudi.openid4vp.internal.*
import io.ktor.client.*
import io.ktor.client.call.*
import io.ktor.client.plugins.*
import io.ktor.client.request.*
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.withContext
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.jsonObject
import java.net.URI
import java.security.PublicKey
import java.security.cert.X509Certificate
import java.time.Clock
import java.time.Instant
import java.util.*
import kotlin.time.Duration
import kotlin.time.toKotlinDuration

internal sealed interface AuthenticatedClient {
    data class Preregistered(val preregisteredClient: PreregisteredClient) : AuthenticatedClient
    data class RedirectUri(val clientId: URI) : AuthenticatedClient
    data class X509SanDns(val clientId: OriginalClientId, val chain: List<X509Certificate>) : AuthenticatedClient
    data class X509SanUri(val clientId: URI, val chain: List<X509Certificate>) : AuthenticatedClient
    data class DIDClient(val client: DID, val publicKey: PublicKey) : AuthenticatedClient
    data class Attested(val clientId: OriginalClientId, val claims: VerifierAttestationClaims) : AuthenticatedClient
}

internal data class AuthenticatedRequest(
    val client: AuthenticatedClient,
    val requestObject: UnvalidatedRequestObject,
)

internal class RequestAuthenticator(siopOpenId4VPConfig: SiopOpenId4VPConfig, httpClient: HttpClient) {
    private val clientAuthenticator = ClientAuthenticator(siopOpenId4VPConfig)
    private val signatureVerifier = JarJwtSignatureVerifier(siopOpenId4VPConfig, httpClient)

    suspend fun authenticate(request: FetchedRequest): AuthenticatedRequest = coroutineScope {
        val client = clientAuthenticator.authenticateClient(request)
        when (request) {
            is FetchedRequest.Plain -> {
                AuthenticatedRequest(client, request.requestObject)
            }

            is FetchedRequest.JwtSecured -> {
                with(signatureVerifier) { verifySignature(client, request.jwt) }
                AuthenticatedRequest(client, request.jwt.requestObject())
            }
        }
    }
}

internal class ClientAuthenticator(private val siopOpenId4VPConfig: SiopOpenId4VPConfig) {
    suspend fun authenticateClient(request: FetchedRequest): AuthenticatedClient {
        val requestObject = when (request) {
            is FetchedRequest.JwtSecured -> request.jwt.requestObject()
            is FetchedRequest.Plain -> request.requestObject
        }

        val (originalClientId, clientIdScheme) = originalClientIdAndScheme(requestObject)
        return when (clientIdScheme) {
            is Preregistered -> {
                val registeredClient = clientIdScheme.clients[originalClientId]
                ensureNotNull(registeredClient) { RequestValidationError.InvalidClientId.asException() }
                if (request is FetchedRequest.JwtSecured) {
                    ensureNotNull(registeredClient.jarConfig) {
                        invalidScheme("$registeredClient cannot place signed request")
                    }
                }
                AuthenticatedClient.Preregistered(registeredClient)
            }

            SupportedClientIdScheme.RedirectUri -> {
                ensure(request is FetchedRequest.Plain) {
                    invalidScheme("${clientIdScheme.scheme()} cannot be used in signed request")
                }
                val originalClientIdAsUri =
                    originalClientId.asURI { RequestValidationError.InvalidClientId.asException() }.getOrThrow()
                AuthenticatedClient.RedirectUri(originalClientIdAsUri)
            }

            is SupportedClientIdScheme.X509SanDns -> {
                ensure(request is FetchedRequest.JwtSecured) {
                    invalidScheme("${clientIdScheme.scheme()} cannot be used in unsigned request")
                }
                val chain = x5c(originalClientId, request, clientIdScheme.trust) {
                    val dnsNames = sanOfDNSName().getOrNull()
                    ensureNotNull(dnsNames) { invalidJarJwt("Certificates misses DNS names") }
                }
                AuthenticatedClient.X509SanDns(originalClientId, chain)
            }

            is SupportedClientIdScheme.X509SanUri -> {
                ensure(request is FetchedRequest.JwtSecured) {
                    invalidScheme("${clientIdScheme.scheme()} cannot be used in unsigned request")
                }
                val chain = x5c(originalClientId, request, clientIdScheme.trust) {
                    val dnsNames = sanOfUniformResourceIdentifier().getOrNull()
                    ensureNotNull(dnsNames) { invalidJarJwt("Certificates misses URI names") }
                }
                val originalClientIdAsUri =
                    originalClientId.asURI { RequestValidationError.InvalidClientId.asException() }.getOrThrow()
                AuthenticatedClient.X509SanUri(originalClientIdAsUri, chain)
            }

            is SupportedClientIdScheme.DID -> {
                ensure(request is FetchedRequest.JwtSecured) {
                    invalidScheme("${clientIdScheme.scheme()} cannot be used in unsigned request")
                }
                val originalClientIdAsDID = ensureNotNull(DID.parse(originalClientId).getOrNull()) {
                    RequestValidationError.InvalidClientId.asException()
                }
                val clientPubKey = lookupKeyByDID(request, originalClientIdAsDID, clientIdScheme.lookup)
                AuthenticatedClient.DIDClient(originalClientIdAsDID, clientPubKey)
            }

            is SupportedClientIdScheme.VerifierAttestation -> {
                ensure(request is FetchedRequest.JwtSecured) {
                    invalidScheme("${clientIdScheme.scheme()} cannot be used in unsigned request")
                }
                val attestedClaims =
                    verifierAttestation(siopOpenId4VPConfig.clock, clientIdScheme, request, originalClientId)
                AuthenticatedClient.Attested(originalClientId, attestedClaims)
            }
        }
    }

    private fun originalClientIdAndScheme(requestObject: UnvalidatedRequestObject): Pair<OriginalClientId, SupportedClientIdScheme> {
        val clientId = ensureNotNull(requestObject.clientId) { RequestValidationError.MissingClientId.asException() }
        val verifierId =
            VerifierId.parse(clientId).getOrElse { throw invalidScheme("Invalid client_id: ${it.message}") }
        val supportedClientIdScheme = siopOpenId4VPConfig.supportedClientIdScheme(verifierId.scheme)
        ensureNotNull(supportedClientIdScheme) { RequestValidationError.UnsupportedClientIdScheme.asException() }
        return verifierId.originalClientId to supportedClientIdScheme
    }

    private fun x5c(
        originalClientId: OriginalClientId,
        request: FetchedRequest.JwtSecured,
        trust: X509CertificateTrust,
        subjectAlternativeNames: X509Certificate.() -> List<String>,
    ): List<X509Certificate> {
        val x5c = request.jwt.header?.x509CertChain
        ensureNotNull(x5c) { invalidJarJwt("Missing x5c") }
        val pubCertChain = x5c.mapNotNull { runCatching { X509CertUtils.parse(it.decode()) }.getOrNull() }
        ensure(pubCertChain.isNotEmpty()) { invalidJarJwt("Invalid x5c") }

        val alternativeNames = pubCertChain[0].subjectAlternativeNames()
        ensure(originalClientId in alternativeNames) {
            invalidJarJwt("ClientId not found in certificate's subject alternative names")
        }
        ensure(trust.isTrusted(pubCertChain)) { invalidJarJwt("Untrusted x5c") }
        return pubCertChain
    }
}

private suspend fun lookupKeyByDID(
    request: FetchedRequest.JwtSecured,
    clientId: DID,
    lookupPublicKeyByDIDUrl: LookupPublicKeyByDIDUrl,
): PublicKey = withContext(Dispatchers.IO) {
    val keyUrl: AbsoluteDIDUrl = run {
        val kid = ensureNotNull(request.jwt.header?.keyID) {
            invalidJarJwt("Missing kid for client_id $clientId")
        }
        ensureNotNull(AbsoluteDIDUrl.parse(kid).getOrNull()) {
            invalidJarJwt("kid should be DID URL")
        }
    }
    ensure(keyUrl.toString().startsWith(clientId.toString())) {
        invalidJarJwt("kid should be DID URL sub-resource of $clientId but is $keyUrl")
    }
    val key = runCatching { lookupPublicKeyByDIDUrl.resolveKey(keyUrl.uri) }.getOrNull()
    ensureNotNull(key) {
        RequestValidationError.DIDResolutionFailed(keyUrl.toString()).asException()
    }
}

private fun verifierAttestation(
    clock: Clock,
    supportedScheme: SupportedClientIdScheme.VerifierAttestation,
    request: FetchedRequest.JwtSecured,
    originalClientId: OriginalClientId,
): VerifierAttestationClaims {
    val (trust, skew) = supportedScheme
    fun invalidVerifierAttestationJwt(cause: String?) =
        invalidJarJwt("Invalid VerifierAttestation JWT. Details: $cause")

    val verifierAttestationJwt = run {
        val jwtString = request.jwt.header.customParams["jwt"]
        ensureNotNull(jwtString) { invalidJarJwt("Missing jwt JOSE Header") }
        ensure(jwtString is String) { invalidJarJwt("jwt JOSE Header doesn't contain a JWT") }

        val parsedJwt = runCatching { SignedJWT.parse(jwtString) }.getOrElse { error ->
            throw invalidVerifierAttestationJwt("Cannot be parsed  $error")
        }
        val expectedType = "verifier-attestation+jwt"
        ensure(parsedJwt.header.type == JOSEObjectType(expectedType)) {
            invalidVerifierAttestationJwt("typ is not $expectedType ")
        }
        parsedJwt.apply {
            runCatching { verify(trust) }.getOrElse { throw invalidVerifierAttestationJwt("Not trusted. $it") }
        }
    }

    val verifierAttestationClaimSet = try {
        TimeChecks(clock, skew.toKotlinDuration()).verify(verifierAttestationJwt.jwtClaimsSet, null)
        verifierAttestationJwt.verifierAttestationClaims()
    } catch (t: Throwable) {
        throw invalidVerifierAttestationJwt(t.message)
    }
    ensure(verifierAttestationClaimSet.sub == originalClientId) {
        invalidVerifierAttestationJwt("sub claim and authorization's request client_id don't match")
    }

    return verifierAttestationClaimSet
}

/**
 * Validates a JWT that represents an Authorization Request according to RFC9101
 *
 * @param siopOpenId4VPConfig wallet's configuration
 */
private class JarJwtSignatureVerifier(
    private val siopOpenId4VPConfig: SiopOpenId4VPConfig,
    private val httpClient: HttpClient,
) {

    @Throws(AuthorizationRequestException::class)
    suspend fun verifySignature(client: AuthenticatedClient, signedJwt: SignedJWT) {
        try {
            val jwtProcessor = DefaultJWTProcessor<SecurityContext>().apply {
                jwsTypeVerifier = DefaultJOSEObjectTypeVerifier(JOSEObjectType(OpenId4VPSpec.AUTHORIZATION_REQUEST_OBJECT_TYPE))
                jwsKeySelector = jwsKeySelector(client)
                jwtClaimsSetVerifier =
                    TimeChecks(siopOpenId4VPConfig.clock, siopOpenId4VPConfig.jarClockSkew.toKotlinDuration())
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
            is AuthenticatedClient.Preregistered ->
                getPreRegisteredClientJwsSelector(client)

            is AuthenticatedClient.X509SanUri ->
                JWSKeySelector<SecurityContext> { _, _ -> listOf(client.chain[0].publicKey) }

            is AuthenticatedClient.X509SanDns ->
                JWSKeySelector<SecurityContext> { _, _ -> listOf(client.chain[0].publicKey) }

            is AuthenticatedClient.RedirectUri ->
                throw RequestValidationError.UnsupportedClientIdScheme.asException()

            is AuthenticatedClient.DIDClient ->
                JWSKeySelector<SecurityContext> { _, _ -> listOf(client.publicKey) }

            is AuthenticatedClient.Attested ->
                JWSKeySelector<SecurityContext> { _, _ -> listOf(client.claims.verifierPubJwk.toPublicKey()) }
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
                is JwkSetSource.ByReference -> try {
                    val unparsed = httpClient.get(jwkSetSource.jwksUri.toURL()).body<String>()
                    JWKSet.parse(unparsed)
                } catch (e: ClientRequestException) {
                    throw HttpError(e).asException()
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

private fun SignedJWT.requestObject(): UnvalidatedRequestObject {
    fun Map<String, Any?>.asJsonObject(): JsonObject {
        val jsonStr = Gson().toJson(this)
        return Json.parseToJsonElement(jsonStr).jsonObject
    }

    return with(jwtClaimsSet) {
        UnvalidatedRequestObject(
            responseType = getStringClaim("response_type"),
            presentationDefinition = getJSONObjectClaim(OpenId4VPSpec.PRESENTATION_DEFINITION)?.asJsonObject(),
            presentationDefinitionUri = getStringClaim(OpenId4VPSpec.PRESENTATION_DEFINITION_URI),
            dcqlQuery = getJSONObjectClaim(OpenId4VPSpec.DCQL_QUERY)?.asJsonObject(),
            scope = getStringClaim("scope"),
            nonce = getStringClaim("nonce"),
            responseMode = getStringClaim("response_mode"),
            clientMetaData = getJSONObjectClaim("client_metadata")?.asJsonObject(),
            clientId = getStringClaim("client_id"),
            responseUri = getStringClaim(OpenId4VPSpec.RESPONSE_URI),
            redirectUri = getStringClaim("redirect_uri"),
            state = getStringClaim("state"),
            supportedAlgorithm = getStringClaim("supported_algorithm"),
            idTokenType = getStringClaim("id_token_type"),
            transactionData = getStringListClaim(OpenId4VPSpec.TRANSACTION_DATA),
        )
    }
}

internal data class VerifierAttestationClaims(
    val iss: String,
    val sub: String,
    val iat: Instant?,
    val exp: Instant,
    val nbf: Instant?,
    val verifierPubJwk: AsymmetricJWK,
    val redirectUris: List<String>?,
    val responseUris: List<String>?,
)

private fun SignedJWT.verifierAttestationClaims(): VerifierAttestationClaims =
    with(jwtClaimsSet) {
        VerifierAttestationClaims(
            iss = requireNotNull(issuer) { "Missing iss" },
            sub = requireNotNull(subject) { "Missing sub" },
            iat = issueTime?.toInstant(),
            exp = requireNotNull(expirationTime?.toInstant()) { "Missing exp" },
            nbf = notBeforeTime?.toInstant(),
            verifierPubJwk = run {
                val cnf = requireNotNull(getJSONObjectClaim("cnf")) { "Missing cnf" }
                val jwk = runCatching {
                    val jwkObj = requireNotNull(cnf["jwk"]) { "Missing jwk" }
                    JWK.parse(Gson().toJson(jwkObj))
                }.getOrNull()
                requireNotNull(jwk) { "Missing jwk" }
                require(!jwk.isPrivate) { "Not a public JWK" }
                require(jwk is AsymmetricJWK) { "Not a valid JWK" }
                jwk
            },
            redirectUris = getStringListClaim("redirect_uris")?.toList(),
            responseUris = getStringListClaim("response_uris")?.toList(),
        )
    }

private class TimeChecks(
    private val clock: Clock,
    private val skew: Duration,
) : JWTClaimsSetVerifier<SecurityContext> {

    @Throws(BadJWTException::class)
    override fun verify(claimsSet: JWTClaimsSet, context: SecurityContext?) {
        val now = Date.from(clock.instant())
        val skewInSeconds = skew.inWholeSeconds

        val exp = claimsSet.expirationTime
        if (exp != null) {
            if (!DateUtils.isAfter(exp, now, skewInSeconds)) {
                throw BadJWTException("Expired JWT")
            }
        }

        val nbf = claimsSet.notBeforeTime
        if (nbf != null) {
            if (!DateUtils.isBefore(nbf, now, skewInSeconds)) {
                throw BadJWTException("JWT before use time")
            }
        }
    }
}
