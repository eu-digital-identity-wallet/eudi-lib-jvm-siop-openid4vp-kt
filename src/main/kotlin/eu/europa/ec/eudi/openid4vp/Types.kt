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
import com.nimbusds.jose.jwk.JWKSet
import com.nimbusds.jose.jwk.ThumbprintURI
import java.net.URI
import java.net.URL

data class ClientMetaData(
    val jwkSet: JWKSet? = null,
    val subjectSyntaxTypesSupported: List<SubjectSyntaxType>? = null,
    val authorizationSignedResponseAlg: JWSAlgorithm? = null,
    val authorizationEncryptedResponseAlg: JWEAlgorithm? = null,
    val authorizationEncryptedResponseEnc: EncryptionMethod? = null,
) : java.io.Serializable

sealed interface SubjectSyntaxType : java.io.Serializable {

    companion object {
        fun isValid(value: String): Boolean = DecentralizedIdentifier.isValid(value) || JWKThumbprint.isValid(value)
    }

    data class DecentralizedIdentifier(
        val method: String,
    ) : SubjectSyntaxType {
        companion object {

            fun isValid(value: String): Boolean =
                !(value.isEmpty() || value.count { it == ':' } != 1 || value.split(':').any { it.isEmpty() })

            fun parse(value: String): DecentralizedIdentifier =
                when {
                    value.isEmpty() -> error("Cannot create DID from $value: Empty value passed")
                    value.count { it == ':' } != 1 -> error("Cannot create DID from $value: Wrong syntax")
                    value.split(':')
                        .any { it.isEmpty() } -> error("Cannot create DID from $value: DID components cannot be empty")

                    else -> DecentralizedIdentifier(value.split(':')[1])
                }
        }
    }

    data object JWKThumbprint : SubjectSyntaxType {
        private fun readResolve(): Any = JWKThumbprint
        fun isValid(value: String): Boolean = value != ThumbprintURI.PREFIX
    }
}

@JvmInline
value class Scope private constructor(val value: String) {
    fun items(): List<String> = itemsOf(value)

    companion object {
        fun make(s: String): Scope? {
            val trimmed = s.trim()
            val scopeItems: List<String> = itemsOf(trimmed)
            return if (scopeItems.isEmpty()) {
                null
            } else {
                Scope(trimmed)
            }
        }

        private fun itemsOf(s: String): List<String> = s.split(" ")
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

    EntityId,

    DID,

    X509_SAN_URI,

    X509_SAN_DNS,
    ;

    companion object {

        fun make(s: String): ClientIdScheme? = when (s) {
            "pre-registered" -> PreRegistered
            "redirect_uri" -> RedirectUri
            "entity_id" -> EntityId
            "did" -> DID
            "x509_san_uri" -> X509_SAN_URI
            "x509_san_dns" -> X509_SAN_DNS
            else -> null
        }
    }
}

/**
 * @see <a href="https://openid.net/specs/oauth-v2-multiple-response-types-1_0.html">https://openid.net/specs/oauth-v2-multiple-response-types-1_0.html</a>
 */
sealed interface ResponseMode : java.io.Serializable {

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

    fun uri(): URI = when (this) {
        is DirectPost -> responseURI.toURI()
        is DirectPostJwt -> responseURI.toURI()
        is Fragment -> redirectUri
        is FragmentJwt -> redirectUri
        is Query -> redirectUri
        is QueryJwt -> redirectUri
    }
}

enum class ResponseType {
    VpToken,
    IdToken,
    VpAndIdToken,
}

typealias Jwt = String
typealias VpToken = String

enum class IdTokenType {
    SubjectSigned,
    AttesterSigned,
}

interface AuthorizationResponseSigner : JWSSigner {
    fun getKeyId(): String
}

sealed interface JarmOption {
    data class SignedResponse(
        val responseSigningAlg: JWSAlgorithm,
        val responseSigner: AuthorizationResponseSigner,
    ) : JarmOption {
        init {
            require(responseSigningAlg in responseSigner.supportedJWSAlgorithms()) {
                "$responseSigningAlg is not supported by given signer"
            }
        }
    }

    data class EncryptedResponse(
        val responseEncryptionAlg: JWEAlgorithm,
        val responseEncryptionEnc: EncryptionMethod,
        val encryptionKeySet: JWKSet,
    ) : JarmOption

    data class SignedAndEncryptedResponse(
        val signedResponse: SignedResponse,
        val encryptResponse: EncryptedResponse,
    ) : JarmOption
}

data class JarmSpec(val holderId: String, val jarmOption: JarmOption) {
    init {
        require(holderId.isNotEmpty()) { "HolderId cannot be null or empty" }
    }
}
