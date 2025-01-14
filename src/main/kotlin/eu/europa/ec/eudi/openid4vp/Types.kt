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
import com.nimbusds.jose.jwk.JWKSet
import com.nimbusds.jose.util.Base64URL
import kotlinx.serialization.json.JsonObject
import java.io.Serializable
import java.net.URI
import java.net.URL

sealed interface SubjectSyntaxType : Serializable {

    @JvmInline
    value class DecentralizedIdentifier(val method: String) : SubjectSyntaxType

    data object JWKThumbprint : SubjectSyntaxType {
        private fun readResolve(): Any = JWKThumbprint
    }
}

@JvmInline
value class Scope private constructor(val value: String) {
    fun items(): List<String> = value.split(" ")

    companion object {
        fun make(s: String): Scope? = s.trim()
            .takeIf { trimmed -> trimmed.split(" ").isNotEmpty() }
            ?.let { Scope(it) }
    }
}

enum class ClientIdScheme {
    /**
     * This value represents the RFC6749 default behavior,
     * i.e., the Client Identifier needs to be known to the Wallet in advance of the Authorization Request
     * The Verifier's metadata is obtained using (RFC7591) or through out-of-band mechanisms.
     */
    PreRegistered,

    /**
     * This value indicates that the Verifier's Redirect URI is also
     * the value of the Client Identifier. In this case,
     * the Authorization Request MUST NOT be signed,
     * the Verifier MAY omit the redirect_uri Authorization Request parameter,
     * and all Client metadata parameters MUST be passed using the client_metadata
     * or client_metadata_uri parameter defined
     */
    RedirectUri,

    /**
     * This value indicates that the Client Identifier is an Entity Identifier
     * defined in OpenID Federation.
     */
    HTTPS,

    /**
     * This value indicates that the Client Identifier is a DID
     */
    DID,

    /**
     * When the Client Identifier Scheme is x509_san_uri, the Client Identifier
     * MUST be a URI and match a uniformResourceIdentifier Subject Alternative Name (SAN) RFC5280
     * entry in the leaf certificate passed with the request
     */
    X509_SAN_URI,

    /**
     * When the Client Identifier Scheme is x509_san_dns, the Client Identifier
     * MUST be a DNS name and match a dNSName Subject Alternative Name (SAN) RFC5280
     * entry in the leaf certificate passed with the request
     */
    X509_SAN_DNS,

    /**
     * This Client Identifier Scheme allows the Verifier
     * to authenticate using a JWT that is bound to a certain public key
     */
    VERIFIER_ATTESTATION,

    ;

    fun value(): String = when (this) {
        PreRegistered -> PRE_REGISTERED_NAME
        RedirectUri -> REDIRECT_URI_NAME
        HTTPS -> HTTPS_NAME
        DID -> DID_NAME
        X509_SAN_URI -> X509_SAN_URI_NAME
        X509_SAN_DNS -> X509_SAN_DNS_NAME
        VERIFIER_ATTESTATION -> VERIFIER_ATTESTATION_NAME
    }

    companion object {
        private const val PRE_REGISTERED_NAME = "pre-registered"
        private const val REDIRECT_URI_NAME = "redirect_uri"
        private const val HTTPS_NAME = "https"
        private const val DID_NAME = "did"
        private const val X509_SAN_URI_NAME = "x509_san_uri"
        private const val X509_SAN_DNS_NAME = "x509_san_dns"
        private const val VERIFIER_ATTESTATION_NAME = "verifier_attestation"

        fun make(s: String): ClientIdScheme? = when (s) {
            PRE_REGISTERED_NAME -> PreRegistered
            REDIRECT_URI_NAME -> RedirectUri
            HTTPS_NAME -> HTTPS
            DID_NAME -> DID
            X509_SAN_URI_NAME -> X509_SAN_URI
            X509_SAN_DNS_NAME -> X509_SAN_DNS
            VERIFIER_ATTESTATION_NAME -> VERIFIER_ATTESTATION
            else -> null
        }
    }
}

/**
 * @see <a href="https://openid.net/specs/oauth-v2-multiple-response-types-1_0.html">https://openid.net/specs/oauth-v2-multiple-response-types-1_0.html</a>
 */
sealed interface ResponseMode : Serializable {

    /**
     * In this mode, Authorization Response parameters are encoded
     * in the query string added to the redirect_uri when redirecting back to the Client.
     */
    data class Query(val redirectUri: URI) : ResponseMode
    data class QueryJwt(val redirectUri: URI) : ResponseMode

    /**
     * In this mode, Authorization Response parameters
     * are encoded in the fragment added to the redirect_uri when redirecting back to the Client.
     */
    data class Fragment(val redirectUri: URI) : ResponseMode
    data class FragmentJwt(val redirectUri: URI) : ResponseMode
    data class DirectPost(val responseURI: URL) : ResponseMode
    data class DirectPostJwt(val responseURI: URL) : ResponseMode
}

typealias Jwt = String

sealed interface VerifiablePresentation {

    @JvmInline
    value class Generic(val value: String) : VerifiablePresentation

    @JvmInline
    value class MsoMdoc(val value: String) : VerifiablePresentation

    @JvmInline
    value class JsonObj(val value: JsonObject) : VerifiablePresentation
}

data class VpToken(
    val verifiablePresentations: List<VerifiablePresentation>,
    val apu: Base64URL? = null,
) {

    init {
        require(verifiablePresentations.isNotEmpty())
    }

    companion object {

        fun Generic(vararg values: String) =
            VpToken(
                verifiablePresentations = values.map { VerifiablePresentation.Generic(it) },
            )

        fun MsoMdoc(apu: Base64URL, vararg values: String) = VpToken(
            verifiablePresentations = values.map { VerifiablePresentation.MsoMdoc(it) },
            apu = apu,
        )
    }
}

/**
 * The type of the `id_token`
 * the client (verifier party) requested
 */
enum class IdTokenType {
    SubjectSigned,
    AttesterSigned,
}

/**
 * The client's (verifier) requirement to
 * reply to an authorization request with JARM
 */
sealed interface JarmRequirement : Serializable {
    /**
     * Client requires JARM signed response using the [responseSigningAlg]
     * signing algorithm
     */
    data class Signed(val responseSigningAlg: JWSAlgorithm) : JarmRequirement

    /**
     * Client requires JARM encrypted response using the
     * provided [algorithm][responseEncryptionAlg], [encoding method][responseEncryptionEnc]
     * and [encryption key][encryptionKeySet]
     */
    data class Encrypted(
        val responseEncryptionAlg: JWEAlgorithm,
        val responseEncryptionEnc: EncryptionMethod,
        val encryptionKeySet: JWKSet,
    ) : JarmRequirement

    /**
     * Client requires JARM signed and (then) encrypted
     * using the provided [signing][signed] and [encryption][encryptResponse]
     * specifications
     */
    data class SignedAndEncrypted(val signed: Signed, val encryptResponse: Encrypted) : JarmRequirement
}
