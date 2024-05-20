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
package eu.europa.ec.eudi.openid4vp

import com.nimbusds.jose.*
import com.nimbusds.jose.crypto.ECDSASigner
import com.nimbusds.jose.crypto.RSASSASigner
import com.nimbusds.jose.jwk.ECKey
import com.nimbusds.jose.jwk.RSAKey
import com.nimbusds.oauth2.sdk.id.Issuer
import eu.europa.ec.eudi.openid4vp.JarmConfiguration.*
import eu.europa.ec.eudi.openid4vp.SiopOpenId4VPConfig.Companion.SelfIssued
import eu.europa.ec.eudi.prex.PresentationDefinition
import kotlinx.serialization.json.JsonObject
import java.net.URI
import java.security.PublicKey
import java.security.cert.X509Certificate
import java.time.Clock
import java.time.Duration

sealed interface JwkSetSource {
    data class ByValue(val jwks: JsonObject) : JwkSetSource
    data class ByReference(val jwksUri: URI) : JwkSetSource
}

/**
 * The out-of-band knowledge of a Verifier, used in [SupportedClientIdScheme.Preregistered]

 * @param clientId the client id of a trusted verifier
 * @param legalName the name of the trusted verifier
 * @param jarConfig in case, verifier communicates his request using JAR, the signing algorithm
 * that is uses to sign his request and a [way][JwkSetSource] to obtain his public key
 *
 */
data class PreregisteredClient(
    val clientId: String,
    val legalName: String,
    val jarConfig: Pair<JWSAlgorithm, JwkSetSource>? = null,
)

fun interface X509CertificateTrust {
    fun isTrusted(chain: List<X509Certificate>): Boolean
}

fun interface LookupPublicKeyByDIDUrl {
    suspend fun resolveKey(didUrl: URI): PublicKey?
}

/**
 * The Client identifier scheme supported (or trusted) by the wallet.
 */
sealed interface SupportedClientIdScheme {

    /**
     * The Client Identifier is known to the Wallet in advance of the Authorization Request.
     */
    data class Preregistered(val clients: Map<String, PreregisteredClient>) : SupportedClientIdScheme {
        constructor(vararg clients: PreregisteredClient) : this(clients.toList().associateBy { it.clientId })
    }

    /**
     * Wallet trusts verifiers that are able to present a Client Identifier which is a URI and
     * match a uniformResourceIdentifier Subject Alternative Name (SAN) RFC5280 entry in the
     * leaf certificate passed with the request.
     *
     * In this scheme, Verifier must always sign his request (JAR)
     *
     * @param trust a function that accepts a chain of certificates (contents of `x5c` claim) and
     * indicates whether is trusted or not
     */
    data class X509SanUri(val trust: X509CertificateTrust) : SupportedClientIdScheme

    /**
     * Wallet trusts verifiers that are able to present a Client Identifier which is a DNS name and
     * matches a dNSName Subject Alternative Name (SAN) RFC5280 entry in the
     * leaf certificate passed with the request.
     *
     * In this scheme, Verifier must always sign his request (JAR)
     *
     * @param trust a function that accepts a chain of certificates (contents of `x5c` claim) and
     * indicates whether is trusted or not
     */
    data class X509SanDns(val trust: X509CertificateTrust) : SupportedClientIdScheme

    /**
     * Wallet trusts verifiers that present an authorization request having a redirect URI
     * equal to the value of the Client Identifier.
     *
     * In this scheme, Verifier must NOT sign his request
     */
    data object RedirectUri : SupportedClientIdScheme

    /**
     * Wallet trusts verifiers that are able to present a client identifier which is a DID
     *
     * In this scheme, Verifier must always sign his request (JAR), signed by a key
     * that can be referenced via the DID
     *
     * @param lookup a function for getting the public key of the verifier by
     * resolving a given DID URL
     */
    data class DID(val lookup: LookupPublicKeyByDIDUrl) : SupportedClientIdScheme

    /**
     * Wallet trust verifiers that are able to present a signed Verifier Attestation, which
     * is issued by a party trusted by the Wallet
     *
     * In this scheme, Verifier must always sign his request (JAR), having in its JOSE
     * header a Verifier Attestation JWT under `jwt` claim
     *
     * @param trust a function for verifying the digital signature of the Verifier Attestation JWT.
     */
    data class VerifierAttestation(val trust: JWSVerifier) : SupportedClientIdScheme

    fun scheme(): ClientIdScheme = when (this) {
        is DID -> ClientIdScheme.DID
        is Preregistered -> ClientIdScheme.PreRegistered
        RedirectUri -> ClientIdScheme.RedirectUri
        is VerifierAttestation -> ClientIdScheme.VERIFIER_ATTESTATION
        is X509SanDns -> ClientIdScheme.X509_SAN_DNS
        is X509SanUri -> ClientIdScheme.X509_SAN_URI
    }
}

/**
 * Configurations options for OpenId4VP
 *
 * @param presentationDefinitionUriSupported indicates whether wallet should fetch a presentation definition
 * which is communicated by the verifier by reference using `presentation_definition_uri`.
 * @param knownPresentationDefinitionsPerScope a set of presentation definitions that a verifier may request via
 * a pre-agreed scope (instead of explicitly using presentation_definition or presentation_definition_uri)
 */
data class VPConfiguration(
    val presentationDefinitionUriSupported: Boolean,
    val knownPresentationDefinitionsPerScope: Map<String, PresentationDefinition>,
) {
    companion object {
        /**
         * A default [VPConfiguration] which enables fetching presentation definitions by reference and
         * doesn't contain any [VPConfiguration.knownPresentationDefinitionsPerScope]
         */
        val Default = VPConfiguration(true, emptyMap())
    }
}

interface JarmSigner : JWSSigner {
    fun getKeyId(): String

    companion object {
        operator fun invoke(rsaKey: RSAKey): JarmSigner =
            object : JarmSigner, JWSSigner by RSASSASigner(rsaKey) {
                override fun getKeyId(): String = rsaKey.keyID
            }

        operator fun invoke(rsaKey: ECKey): JarmSigner =
            object : JarmSigner, JWSSigner by ECDSASigner(rsaKey) {
                override fun getKeyId(): String = rsaKey.keyID
            }
    }
}

/**
 * Configurations options for encrypting and/or signing an authorization response via JARM,
 * if requested by the verifier.
 *
 * The library can be configured to:
 *
 * - Support only [signing][Signing] the authorization response
 * - Support only [encrypting][Encryption] the authorization response
 * - Support both singing and encrypting [SigningAndEncryption] the authorization response
 * - Not support JARM
 *
 * OpenId4VP recommends supporting [encrypting][Encryption] the authorization response
 */
sealed interface JarmConfiguration {

    /**
     * The wallet supports only signed authorization responses
     *
     * @param signer the JWS algorithms that the wallet can use when signing a JARM response
     * @param ttl the time the signed authorization response can live
     */
    data class Signing(
        val signer: JarmSigner,
        val ttl: Duration? = Duration.ofMinutes(10),
    ) : JarmConfiguration {
        init {
            require(signer.supportedJWSAlgorithms().isNotEmpty()) { "At least a algorithm must be provided" }
        }
    }

    /**
     * The wallet supports only encrypted authorization responses
     * @param supportedAlgorithms the JWE algorithms that the wallet can use when encrypting a JARM response
     * @param supportedMethods the JWE encryption methods that the wallet can use when encrypting a JARM
     * response
     */
    data class Encryption(
        val supportedAlgorithms: List<JWEAlgorithm>,
        val supportedMethods: List<EncryptionMethod>,
    ) : JarmConfiguration {
        init {
            require(supportedAlgorithms.isNotEmpty()) { "At least an encryption algorithm must be provided" }
            require(supportedMethods.isNotEmpty()) { "At least an encryption method must be provided" }
        }
    }

    /**
     * The wallet supports any kind of JARM response, signed, encrypted and/or signed and then encrypted
     *
     * @param signing the singing options
     * @param encryption the encryption options
     */
    data class SigningAndEncryption(val signing: Signing, val encryption: Encryption) : JarmConfiguration {

        constructor(
            signer: JarmSigner,
            supportedEncryptionAlgorithms: List<JWEAlgorithm>,
            supportedEncryptionMethods: List<EncryptionMethod>,
        ) : this(
            Signing(signer),
            Encryption(supportedEncryptionAlgorithms, supportedEncryptionMethods),
        )
    }

    /**
     * Wallet doesn't support replying using JARM
     */
    data object NotSupported : JarmConfiguration
}

fun JarmConfiguration.signingConfig(): Signing? = when (this) {
    is Signing -> this
    is Encryption -> null
    is SigningAndEncryption -> signing
    NotSupported -> null
}

fun JarmConfiguration.encryptionConfig(): Encryption? = when (this) {
    is Signing -> null
    is Encryption -> this
    is SigningAndEncryption -> encryption
    NotSupported -> null
}

/**
 * Wallet configuration options for SIOP & OpenId4VP protocols.
 *
 * At minimum, a wallet configuration should define at least a [supportedClientIdSchemes]
 *
 * @param issuer an optional id for the wallet. If not provided defaults to [SelfIssued].
 * @param jarmConfiguration whether wallet supports JARM. If not specified, it takes the default value
 * [JarmConfiguration.NotSupported].
 * @param vpConfiguration options about OpenId4VP. If not provided, [VPConfiguration.Default] is being used.
 * @param clock the system Clock. If not provided system's default clock will be used.
 * @param supportedClientIdSchemes the client id schemes that are supported/trusted by the wallet
 */
data class SiopOpenId4VPConfig(
    val issuer: Issuer? = SelfIssued,
    val jarmConfiguration: JarmConfiguration = NotSupported,
    val vpConfiguration: VPConfiguration = VPConfiguration.Default,
    val clock: Clock = Clock.systemDefaultZone(),
    val supportedClientIdSchemes: List<SupportedClientIdScheme>,
) {
    init {
        require(supportedClientIdSchemes.isNotEmpty()) { "At least a supported client id scheme must be provided" }
    }

    constructor(
        issuer: Issuer? = SelfIssued,
        jarmConfiguration: JarmConfiguration = NotSupported,
        vpConfiguration: VPConfiguration = VPConfiguration.Default,
        clock: Clock,
        vararg supportedClientIdSchemes: SupportedClientIdScheme,
    ) : this(issuer, jarmConfiguration, vpConfiguration, clock, supportedClientIdSchemes.toList())

    companion object {
        /**
         * Identifies the wallet as `https://self-issued.me/v2`
         */
        val SelfIssued = Issuer(URI.create("https://self-issued.me/v2"))
    }
}

internal fun SiopOpenId4VPConfig.supportedClientIdScheme(scheme: ClientIdScheme): SupportedClientIdScheme? =
    supportedClientIdSchemes.firstOrNull { it.scheme() == scheme }
