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
import com.nimbusds.jose.util.JSONObjectUtils
import com.nimbusds.jose.util.X509CertUtils
import com.nimbusds.jwt.JWTClaimsSet
import com.nimbusds.jwt.SignedJWT
import com.nimbusds.jwt.proc.BadJWTException
import com.nimbusds.jwt.proc.DefaultJWTProcessor
import com.nimbusds.jwt.proc.JWTClaimsSetVerifier
import com.nimbusds.jwt.util.DateUtils
import eu.europa.ec.eudi.openid4vp.*
import eu.europa.ec.eudi.openid4vp.RequestValidationError.NoMatchingPrefixInMultiSignedRequest
import eu.europa.ec.eudi.openid4vp.SupportedClientIdPrefix.Preregistered
import eu.europa.ec.eudi.openid4vp.internal.*
import eu.europa.ec.eudi.openid4vp.internal.JwsJson.Companion.flatten
import eu.europa.ec.eudi.openid4vp.internal.request.AuthenticatedClient.*
import io.ktor.client.*
import io.ktor.client.call.*
import io.ktor.client.plugins.*
import io.ktor.client.request.*
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.withContext
import java.net.URI
import java.security.MessageDigest
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
    data class DecentralizedIdentifier(val client: DID, val publicKey: PublicKey) : AuthenticatedClient
    data class VerifierAttestation(val clientId: OriginalClientId, val claims: VerifierAttestationClaims) : AuthenticatedClient
    data class X509SanDns(val clientId: OriginalClientId, val chain: List<X509Certificate>) : AuthenticatedClient
    data class X509Hash(val clientId: OriginalClientId, val chain: List<X509Certificate>) : AuthenticatedClient
    data class Origin(val clientId: OriginalClientId) : AuthenticatedClient
}

internal data class AuthenticatedRequest(
    val client: AuthenticatedClient,
    val requestObject: UnvalidatedRequestObject,
)

internal class RequestAuthenticator(siopOpenId4VPConfig: SiopOpenId4VPConfig, httpClient: HttpClient) {
    private val clientAuthenticator = ClientAuthenticator(siopOpenId4VPConfig)
    private val signatureVerifier = JarJwtSignatureVerifier(siopOpenId4VPConfig, httpClient)

    suspend fun authenticateRequestOverDCApi(origin: String, request: ReceivedRequest): AuthenticatedRequest = coroutineScope {
        val (client, signedJwt) = clientAuthenticator.authenticateClientOverDCApi(origin, request)
        when (request) {
            is ReceivedRequest.Unsigned -> {
                AuthenticatedRequest(client, request.requestObject)
            }
            is ReceivedRequest.Signed -> {
                requireNotNull(signedJwt) {
                    "Expected a signed request but was not."
                }
                val requestObject = signedJwt.requestObject()
                ensure(requestObject.expectedOrigins != null) {
                    RequestValidationError.MissingExpectedOrigins.asException()
                }
                ensure(origin in requestObject.expectedOrigins) {
                    RequestValidationError.UnexpectedOrigin.asException()
                }
                with(signatureVerifier) { verifySignature(client, signedJwt) }
                AuthenticatedRequest(client, requestObject)
            }
        }
    }

    suspend fun authenticateRequestOverHttp(request: ReceivedRequest): AuthenticatedRequest = coroutineScope {
        val client = clientAuthenticator.authenticateClientOverHttp(request)
        when (request) {
            is ReceivedRequest.Unsigned -> {
                AuthenticatedRequest(client, request.requestObject)
            }
            is ReceivedRequest.Signed -> {
                val signedJwt = request.ensureSingleSignedRequest()
                with(signatureVerifier) { verifySignature(client, signedJwt) }
                AuthenticatedRequest(client, signedJwt.requestObject())
            }
        }
    }
}

internal class ClientAuthenticator(private val siopOpenId4VPConfig: SiopOpenId4VPConfig) {

    /**
     * In case of DC API channel client_id is present per case:
     * - When request is unsinged is not included in request and is implied to be 'origin:<origin as passed from DC API call>'
     * - When request is a JWS in compact serialization client_id is expected to exist in claims
     * - When request is a JWS in JSON serialization client_id must exist in the header of each signature
     */
    suspend fun authenticateClientOverDCApi(origin: String, request: ReceivedRequest): Pair<AuthenticatedClient, SignedJWT?> =
        when (request) {
            is ReceivedRequest.Unsigned ->
                AuthenticatedClient.Origin(origin) to null

            is ReceivedRequest.Signed -> {
                val jwsJson = request.jwsJson
                when (jwsJson) {
                    is JwsJson.Flattened -> {
                        val signedJwt = jwsJson.toSignedJwt()
                        val (originalClientId, clientIdPrefix) = originalClientIdAndPrefix(signedJwt.requestObject())
                        authenticateClientPrefix(originalClientId, clientIdPrefix, signedJwt) to signedJwt
                    }

                    is JwsJson.General -> {
                        val policy = siopOpenId4VPConfig.signedRequestConfiguration.multiSignedRequestsPolicy
                        val (originalClientId, clientIdPrefix, signedJwt) = jwsJson.applyPolicy(policy)
                        authenticateClientPrefix(originalClientId, clientIdPrefix, signedJwt) to signedJwt
                    }
                }
            }
        }

    private fun JwsJson.General.applyPolicy(
        policy: MultiSignedRequestsPolicy,
    ): Triple<OriginalClientId, SupportedClientIdPrefix, SignedJWT> =
        when (policy) {
            is MultiSignedRequestsPolicy.ExpectPrefix ->
                matchExpectedClientPrefix(policy.clientPrefix)

            MultiSignedRequestsPolicy.NotSupported ->
                throw RequestValidationError.MultiSignedRequestsNotSupported.asException()
        }

    /**
     * In case of HTTP channel client_id is mandatory to always exist.
     */
    suspend fun authenticateClientOverHttp(request: ReceivedRequest): AuthenticatedClient {
        val (signedRequest, requestObject) = when (request) {
            is ReceivedRequest.Unsigned -> null to request.requestObject
            is ReceivedRequest.Signed -> {
                val signedRequest = request.ensureSingleSignedRequest()
                signedRequest to signedRequest.requestObject()
            }
        }
        val (originalClientId, clientIdPrefix) = originalClientIdAndPrefix(requestObject)
        return authenticateClientPrefix(originalClientId, clientIdPrefix, signedRequest)
    }

    private fun JwsJson.General.matchExpectedClientPrefix(
        expectedPrefix: ClientIdPrefix,
    ): Triple<OriginalClientId, SupportedClientIdPrefix, SignedJWT> =

        flatten().map { flattened ->
            val signedJwt = flattened.toSignedJwt()
            val clientId = ensureNotNull(signedJwt.header.customParams["client_id"]) {
                RequestValidationError.MissingClientId.asException()
            }
            ensure(clientId is String) { invalidJarJwt("provided client_id cannot be parsed as string") }
            val verifierId = VerifierId.parse(clientId)
                .getOrElse { throw invalidPrefix("Invalid client_id: ${it.message}") }

            if (verifierId.prefix == expectedPrefix) {
                val supportedClientIdPrefix = siopOpenId4VPConfig.supportedClientIdPrefix(verifierId.prefix)
                ensureNotNull(supportedClientIdPrefix) { RequestValidationError.UnsupportedClientIdPrefix.asException() }
                return Triple(verifierId.originalClientId, supportedClientIdPrefix, signedJwt)
            } else
                null
        }.firstOrNull()
            ?: throw NoMatchingPrefixInMultiSignedRequest.asException()

    private suspend fun authenticateClientPrefix(
        originalClientId: OriginalClientId,
        clientIdPrefix: SupportedClientIdPrefix,
        signedRequest: SignedJWT?,
    ): AuthenticatedClient = when (clientIdPrefix) {
        is Preregistered -> {
            val registeredClient = clientIdPrefix.clients[originalClientId]
            ensureNotNull(registeredClient) { RequestValidationError.InvalidClientId.asException() }
            signedRequest?.let {
                ensureNotNull(registeredClient.jarConfig) {
                    invalidPrefix("$registeredClient cannot place signed request")
                }
            }
            AuthenticatedClient.Preregistered(registeredClient)
        }

        SupportedClientIdPrefix.RedirectUri -> {
            ensure(signedRequest == null) {
                invalidPrefix("${clientIdPrefix.prefix()} cannot be used in signed request")
            }
            val originalClientIdAsUri =
                originalClientId.asURI { RequestValidationError.InvalidClientId.asException() }.getOrThrow()
            RedirectUri(originalClientIdAsUri)
        }

        is SupportedClientIdPrefix.X509SanDns -> {
            ensure(signedRequest != null) {
                invalidPrefix("${clientIdPrefix.prefix()} cannot be used in unsigned request")
            }
            val chain = x5c(signedRequest, clientIdPrefix.trust)

            val alternativeNames = chain.first().sanOfDNSName().getOrNull()
            ensureNotNull(alternativeNames) { invalidJarJwt("Certificates misses DNS names") }
            ensure(originalClientId in alternativeNames) {
                invalidJarJwt("ClientId not found in certificate's subject alternative names")
            }

            X509SanDns(originalClientId, chain)
        }

        is SupportedClientIdPrefix.DecentralizedIdentifier -> {
            ensure(signedRequest != null) {
                invalidPrefix("${clientIdPrefix.prefix()} cannot be used in unsigned request")
            }
            val originalClientIdAsDID = ensureNotNull(DID.parse(originalClientId).getOrNull()) {
                RequestValidationError.InvalidClientId.asException()
            }
            val clientPubKey = lookupKeyByDID(signedRequest, originalClientIdAsDID, clientIdPrefix.lookup)
            DecentralizedIdentifier(originalClientIdAsDID, clientPubKey)
        }

        is SupportedClientIdPrefix.VerifierAttestation -> {
            ensure(signedRequest != null) {
                invalidPrefix("${clientIdPrefix.prefix()} cannot be used in unsigned request")
            }
            val attestedClaims =
                verifierAttestation(siopOpenId4VPConfig.clock, clientIdPrefix, signedRequest, originalClientId)
            VerifierAttestation(originalClientId, attestedClaims)
        }

        is SupportedClientIdPrefix.X509Hash -> {
            ensure(signedRequest != null) {
                invalidPrefix("${clientIdPrefix.prefix()} cannot be used in unsigned request")
            }
            val chain = x5c(signedRequest, clientIdPrefix.trust)

            val expectedHash = base64UrlNoPadding.encode(
                MessageDigest.getInstance("SHA-256").digest(chain.first().encoded),
            )
            ensure(expectedHash == originalClientId) {
                invalidJarJwt("ClientId does not match leaf certificate's SHA-256 hash")
            }

            AuthenticatedClient.X509Hash(originalClientId, chain)
        }
    }

    private fun originalClientIdAndPrefix(requestObject: UnvalidatedRequestObject): Pair<OriginalClientId, SupportedClientIdPrefix> {
        val clientId = ensureNotNull(requestObject.clientId) {
            RequestValidationError.MissingClientId.asException()
        }
        val verifierId =
            VerifierId.parse(clientId).getOrElse { throw invalidPrefix("Invalid client_id: ${it.message}") }
        val supportedClientIdPrefix = siopOpenId4VPConfig.supportedClientIdPrefix(verifierId.prefix)
        ensureNotNull(supportedClientIdPrefix) { RequestValidationError.UnsupportedClientIdPrefix.asException() }
        return verifierId.originalClientId to supportedClientIdPrefix
    }

    private fun x5c(
        requestJwt: SignedJWT,
        trust: X509CertificateTrust,
    ): List<X509Certificate> {
        val x5c = requestJwt.header?.x509CertChain
        ensureNotNull(x5c) { invalidJarJwt("Missing x5c") }
        val pubCertChain = x5c.mapNotNull { runCatching { X509CertUtils.parse(it.decode()) }.getOrNull() }
        ensure(pubCertChain.isNotEmpty()) { invalidJarJwt("Invalid x5c") }
        ensure(trust.isTrusted(pubCertChain)) { invalidJarJwt("Untrusted x5c") }
        return pubCertChain
    }
}

private fun ReceivedRequest.Signed.ensureSingleSignedRequest(): SignedJWT =
    ensure(jwsJson is JwsJson.Flattened) {
        invalidJarJwt("Multi-signed authorization requests is not expected.")
    }.let { jwsJson.toSignedJwt() }

private suspend fun lookupKeyByDID(
    signedRequest: SignedJWT,
    clientId: DID,
    lookupPublicKeyByDIDUrl: LookupPublicKeyByDIDUrl,
): PublicKey = withContext(Dispatchers.IO) {
    val keyUrl: AbsoluteDIDUrl = run {
        val kid = ensureNotNull(signedRequest.header?.keyID) {
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
    supportedPrefix: SupportedClientIdPrefix.VerifierAttestation,
    signedRequest: SignedJWT,
    originalClientId: OriginalClientId,
): VerifierAttestationClaims {
    val (trust, skew) = supportedPrefix
    fun invalidVerifierAttestationJwt(cause: String?) =
        invalidJarJwt("Invalid VerifierAttestation JWT. Details: $cause")

    val verifierAttestationJwt = run {
        val jwtString = signedRequest.header.customParams["jwt"]
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

            is AuthenticatedClient.RedirectUri ->
                throw RequestValidationError.UnsupportedClientIdPrefix.asException()

            is AuthenticatedClient.DecentralizedIdentifier ->
                JWSKeySelector<SecurityContext> { _, _ -> listOf(client.publicKey) }

            is AuthenticatedClient.VerifierAttestation ->
                JWSKeySelector<SecurityContext> { _, _ -> listOf(client.claims.verifierPubJwk.toPublicKey()) }

            is AuthenticatedClient.X509SanDns ->
                JWSKeySelector<SecurityContext> { _, _ -> listOf(client.chain[0].publicKey) }

            is AuthenticatedClient.X509Hash ->
                JWSKeySelector<SecurityContext> { _, _ -> listOf(client.chain[0].publicKey) }

            is AuthenticatedClient.Origin ->
                throw RequestValidationError.UnsupportedClientIdPrefix.asException()
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

private fun invalidPrefix(cause: String): AuthorizationRequestException =
    RequestValidationError.InvalidClientIdPrefix(cause).asException()

private fun invalidJarJwt(cause: String): AuthorizationRequestException =
    RequestValidationError.InvalidJarJwt(cause).asException()

internal fun SignedJWT.requestObject(): UnvalidatedRequestObject =
    jsonSupport.decodeFromString(JSONObjectUtils.toJSONString(jwtClaimsSet.toJSONObject()))

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
