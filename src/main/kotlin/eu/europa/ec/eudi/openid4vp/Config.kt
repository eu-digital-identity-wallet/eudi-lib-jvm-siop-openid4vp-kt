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

import com.nimbusds.jose.EncryptionMethod
import com.nimbusds.jose.JWEAlgorithm
import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.JWSSigner
import com.nimbusds.jose.crypto.ECDSASigner
import com.nimbusds.jose.crypto.RSASSASigner
import com.nimbusds.jose.jwk.ECKey
import com.nimbusds.jose.jwk.RSAKey
import eu.europa.ec.eudi.openid4vp.JarmConfiguration.*
import eu.europa.ec.eudi.prex.PresentationDefinition
import kotlinx.serialization.json.JsonObject
import java.io.Serializable
import java.net.URI
import java.security.cert.X509Certificate

sealed interface JwkSetSource {
    data class ByValue(val jwks: JsonObject) : JwkSetSource
    data class ByReference(val jwksUri: URI) : JwkSetSource
}

/**
 * The out-of-band knowledge of a Verifier, used in [SupportedClientIdScheme.Preregistered]

 * @param clientId the client id of a trusted verifier
 * @param jarConfig in case, verifier communicates his request using JAR, the signing algorithm
 * that is uses to sign his request and a [way][JwkSetSource] to obtain his public key
 *
 */
data class PreregisteredClient(
    val clientId: String,
    val jarConfig: Pair<JWSAlgorithm, JwkSetSource>? = null,
)

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
     * @param validator a function that accepts a chain of certificates (contents of `x5c` claim) and
     * indicates whether is trusted or not
     */
    data class X509SanUri(val validator: (List<X509Certificate>) -> Boolean) : SupportedClientIdScheme

    /**
     * Wallet trusts verifiers that are able to present a Client Identifier which is a DNS name and
     * matches a dNSName Subject Alternative Name (SAN) RFC5280 entry in the
     * leaf certificate passed with the request.
     *
     * In this scheme, Verifier must always sign his request (JAR)
     *
     * @param validator a function that accepts a chain of certificates (contents of `x5c` claim) and
     * indicates whether is trusted or not
     */
    data class X509SanDns(val validator: (List<X509Certificate>) -> Boolean) : SupportedClientIdScheme

    /**
     * Wallet trusts verifiers that present an authorization request having a redirect URI
     * equal to the value of the Client Identifier.
     *
     * In this scheme, Verifier must NOT sign his request
     */
    data object RedirectUri : SupportedClientIdScheme
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

interface AuthorizationResponseSigner : JWSSigner {
    fun getKeyId(): String

    companion object {
        operator fun invoke(rsaKey: RSAKey): AuthorizationResponseSigner =
            object : AuthorizationResponseSigner, JWSSigner by RSASSASigner(rsaKey) {
                override fun getKeyId(): String = rsaKey.keyID
            }
        operator fun invoke(rsaKey: ECKey): AuthorizationResponseSigner =
            object : AuthorizationResponseSigner, JWSSigner by ECDSASigner(rsaKey) {
                override fun getKeyId(): String = rsaKey.keyID
            }
    }
}

/**
 * Configurations options for JARM.
 *
 * The library can be configured to:
 *
 * - Support only [signing][Signing]
 * - Support only [encrypting][Encryption]
 * - Support both singing and encryption[SigningAndEncryption]
 * - Not support JARM
 *
 * These options are taken into account only if a verifier requests from
 * wallet to reply with a JARM response.
 */
sealed interface JarmConfiguration : Serializable {

    /**
     * The wallet supports only signed authorization responses
     *
     * @param holderId the contents of the `iss` claim
     * @param signer the JWS algorithms that the wallet can use when signing a JARM response
     */
    data class Signing(
        val holderId: String,
        val signer: AuthorizationResponseSigner,
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
            holderId: String,
            signer: AuthorizationResponseSigner,
            supportedEncryptionAlgorithms: List<JWEAlgorithm>,
            supportedEncryptionMethods: List<EncryptionMethod>,
        ) : this(
            Signing(holderId, signer),
            Encryption(supportedEncryptionAlgorithms, supportedEncryptionMethods),
        )
    }

    /**
     * Wallet doesn't support replying using JARM
     */
    data object NotSupported : JarmConfiguration {
        private fun readResolve(): Any = NotSupported
    }
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
 * @param jarmConfiguration whether wallet supports JARM. If not specified, it takes the default value
 * [JarmConfiguration.NotSupported].
 * @param vpConfiguration options about OpenId4VP. If not provided, [VPConfiguration.Default] is being used.
 * @param supportedClientIdSchemes the client id schemes that are supported/trusted by the wallet
 */
data class SiopOpenId4VPConfig(
    val jarmConfiguration: JarmConfiguration = NotSupported,
    val vpConfiguration: VPConfiguration = VPConfiguration.Default,
    val supportedClientIdSchemes: List<SupportedClientIdScheme>,
) {
    init {
        require(supportedClientIdSchemes.isNotEmpty()) { "At least a supported client id scheme must be provided" }
    }

    constructor(
        jarmConfiguration: JarmConfiguration = NotSupported,
        vpConfiguration: VPConfiguration = VPConfiguration.Default,
        vararg supportedClientIdSchemes: SupportedClientIdScheme,
    ) : this(jarmConfiguration, vpConfiguration, supportedClientIdSchemes.toList())
}

internal fun SiopOpenId4VPConfig.supportedClientIdScheme(scheme: ClientIdScheme): SupportedClientIdScheme? {
    fun SupportedClientIdScheme.scheme(): ClientIdScheme = when (this) {
        is SupportedClientIdScheme.Preregistered -> ClientIdScheme.PreRegistered
        is SupportedClientIdScheme.X509SanUri -> ClientIdScheme.X509_SAN_URI
        is SupportedClientIdScheme.X509SanDns -> ClientIdScheme.X509_SAN_DNS
        SupportedClientIdScheme.RedirectUri -> ClientIdScheme.RedirectUri
    }

    return supportedClientIdSchemes.firstOrNull { it.scheme() == scheme }
}
