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
        PreRegistered -> OpenId4VPSpec.CLIENT_ID_SCHEME_PRE_REGISTERED
        RedirectUri -> OpenId4VPSpec.CLIENT_ID_SCHEME_REDIRECT_URI
        HTTPS -> OpenId4VPSpec.CLIENT_ID_SCHEME_HTTPS
        DID -> OpenId4VPSpec.CLIENT_ID_SCHEME_DID
        X509_SAN_URI -> OpenId4VPSpec.CLIENT_ID_SCHEME_X509_SAN_URI
        X509_SAN_DNS -> OpenId4VPSpec.CLIENT_ID_SCHEME_X509_SAN_DNS
        VERIFIER_ATTESTATION -> OpenId4VPSpec.CLIENT_ID_SCHEME_VERIFIER_ATTESTATION
    }

    companion object {
        fun make(s: String): ClientIdScheme? = when (s) {
            OpenId4VPSpec.CLIENT_ID_SCHEME_PRE_REGISTERED -> PreRegistered
            OpenId4VPSpec.CLIENT_ID_SCHEME_REDIRECT_URI -> RedirectUri
            OpenId4VPSpec.CLIENT_ID_SCHEME_HTTPS -> HTTPS
            OpenId4VPSpec.CLIENT_ID_SCHEME_DID -> DID
            OpenId4VPSpec.CLIENT_ID_SCHEME_X509_SAN_URI -> X509_SAN_URI
            OpenId4VPSpec.CLIENT_ID_SCHEME_X509_SAN_DNS -> X509_SAN_DNS
            OpenId4VPSpec.CLIENT_ID_SCHEME_VERIFIER_ATTESTATION -> VERIFIER_ATTESTATION
            else -> null
        }
    }
}

/**
 * The Original Client Id of a Verifier, i.e. without a Client Id Scheme prefix.
 */
typealias OriginalClientId = String

/**
 * The Client Id of a Verifier as defined by OpenId4Vp.
 *
 * @see <a href="https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#name-client-identifier-scheme-an">https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#name-client-identifier-scheme-an</a>
 */
data class VerifierId(
    val scheme: ClientIdScheme,
    val originalClientId: OriginalClientId,
) {
    val clientId: String = run {
        val prefix = when (scheme) {
            ClientIdScheme.RedirectUri -> OpenId4VPSpec.CLIENT_ID_SCHEME_REDIRECT_URI
            ClientIdScheme.X509_SAN_URI -> OpenId4VPSpec.CLIENT_ID_SCHEME_X509_SAN_URI
            ClientIdScheme.X509_SAN_DNS -> OpenId4VPSpec.CLIENT_ID_SCHEME_X509_SAN_DNS
            ClientIdScheme.VERIFIER_ATTESTATION -> OpenId4VPSpec.CLIENT_ID_SCHEME_VERIFIER_ATTESTATION
            else -> null
        }

        buildString {
            if (prefix != null) {
                append(prefix)
                append(OpenId4VPSpec.CLIENT_ID_SCHEME_SEPARATOR)
            }
            append(originalClientId)
        }
    }

    override fun toString(): String = clientId

    companion object {
        fun parse(clientId: String): Result<VerifierId> = runCatching {
            fun invalid(message: String): Nothing = throw IllegalArgumentException(message)

            if (OpenId4VPSpec.CLIENT_ID_SCHEME_SEPARATOR !in clientId) {
                VerifierId(ClientIdScheme.PreRegistered, clientId)
            } else {
                val parts = clientId.split(OpenId4VPSpec.CLIENT_ID_SCHEME_SEPARATOR, limit = 2)
                val originalClientId = parts[1]
                val scheme = ClientIdScheme.make(parts[0]) ?: invalid("'$clientId' does not contain a valid Client ID Scheme")
                when (scheme) {
                    ClientIdScheme.PreRegistered -> invalid("'${ClientIdScheme.PreRegistered}' cannot be used as a Client ID Scheme")
                    ClientIdScheme.RedirectUri -> VerifierId(scheme, originalClientId)
                    ClientIdScheme.HTTPS -> VerifierId(scheme, clientId)
                    ClientIdScheme.DID -> VerifierId(scheme, clientId)
                    ClientIdScheme.X509_SAN_URI -> VerifierId(scheme, originalClientId)
                    ClientIdScheme.X509_SAN_DNS -> VerifierId(scheme, originalClientId)
                    ClientIdScheme.VERIFIER_ATTESTATION -> VerifierId(scheme, originalClientId)
                }
            }
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
