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
import com.nimbusds.jose.jwk.ThumbprintURI
import kotlinx.serialization.Required
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.JsonObject
import java.net.URI
import java.net.URL

@Serializable
data class UnvalidatedClientMetaData(
    @SerialName("jwks_uri") val jwksUri: String? = null,
    @SerialName("jwks") val jwks: JsonObject? = null,
    @SerialName("id_token_signed_response_alg") val idTokenSignedResponseAlg: String,
    @SerialName("id_token_encrypted_response_alg") val idTokenEncryptedResponseAlg: String,
    @SerialName("id_token_encrypted_response_enc") val idTokenEncryptedResponseEnc: String,
    @SerialName("subject_syntax_types_supported") val subjectSyntaxTypesSupported: List<String>,
    @SerialName("authorization_signed_response_alg") val authorizationSignedResponseAlg: String? = null,
    @SerialName("authorization_encrypted_response_alg") val authorizationEncryptedResponseAlg: String? = null,
    @SerialName("authorization_encrypted_response_enc") val authorizationEncryptedResponseEnc: String? = null,
) : java.io.Serializable

data class ClientMetaData(
    val jwkSet: JWKSet? = null,
    val idTokenJWSAlg: JWSAlgorithm,
    val idTokenJWEAlg: JWEAlgorithm,
    val idTokenJWEEnc: EncryptionMethod,
    val subjectSyntaxTypesSupported: List<SubjectSyntaxType>,
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

    ISO_X509,

    ;

    companion object {

        fun make(s: String): ClientIdScheme? = when (s) {
            "pre-registered" -> PreRegistered
            "redirect_uri" -> RedirectUri
            "entity_id" -> EntityId
            "did" -> DID
            "iso_x509" -> ISO_X509
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
}

enum class ResponseType {
    VpToken,
    IdToken,
    VpAndIdToken,
}

/**
 * The data of an OpenID4VP authorization request or SIOP Authentication request
 * or a combined OpenId4VP & SIOP request
 * without any validation and regardless of the way they sent to the wallet
 */
@Serializable
data class RequestObject(
    @SerialName("client_metadata") val clientMetaData: JsonObject? = null,
    @SerialName("client_metadata_uri") val clientMetadataUri: String? = null,
    @SerialName("client_id_scheme") val clientIdScheme: String? = null,
    @Required val nonce: String? = null,
    @SerialName("client_id") val clientId: String? = null,
    @SerialName("response_type") val responseType: String? = null,
    @SerialName("response_mode") val responseMode: String? = null,
    @SerialName("response_uri") val responseUri: String? = null,
    @SerialName("presentation_definition") val presentationDefinition: JsonObject? = null,
    @SerialName("presentation_definition_uri") val presentationDefinitionUri: String? = null, // Not utilized from ISO-23330-4
    @SerialName("redirect_uri") val redirectUri: String? = null,
    val scope: String? = null,
    @SerialName("supported_algorithm") val supportedAlgorithm: String? = null,
    val state: String? = null, // OpenId4VP specific, not utilized from ISO-23330-4
    @SerialName("id_token_type") val idTokenType: String? = null,
) : java.io.Serializable

typealias Jwt = String
typealias VpToken = String

enum class IdTokenType {
    SubjectSigned,
    AttesterSigned,
}

sealed interface JarmOption {
    data class SignedResponse(
        val responseSigningAlg: JWSAlgorithm,
        val signingKeySet: JWKSet,
    ) : JarmOption

    data class EncryptedResponse(
        val responseEncryptionAlg: JWEAlgorithm,
        val responseEncryptionEnc: EncryptionMethod,
        val encryptionKeySet: JWKSet,
    ) : JarmOption

    data class SignedAndEncryptedResponse(
        val signedResponse: SignedResponse,
        val encryptResponse: EncryptedResponse,
    ) : JarmOption

    companion object {
        fun make(clientMetaData: ClientMetaData, walletOpenId4VPConfig: WalletOpenId4VPConfig): JarmOption? {
            val signed: SignedResponse? = clientMetaData.authorizationSignedResponseAlg?.let {
                SignedResponse(it, walletOpenId4VPConfig.signingKeySet)
            }

            val encrypted: EncryptedResponse? =
                clientMetaData.authorizationEncryptedResponseAlg?.let { jweAlg ->
                    clientMetaData.authorizationEncryptedResponseEnc?.let { encMethod ->
                        clientMetaData.jwkSet?.let { jwkSet ->
                            EncryptedResponse(jweAlg, encMethod, jwkSet)
                        }
                    }
                }

            return when {
                signed != null && encrypted != null -> SignedAndEncryptedResponse(signed, encrypted)
                signed != null && encrypted == null -> signed
                signed == null && encrypted != null -> encrypted
                else -> null
            }
        }
    }
}

data class JarmSpec(val holderId: String, val jarmOption: JarmOption) {

    companion object {
        fun make(clientMetaData: ClientMetaData, walletOpenId4VPConfig: WalletOpenId4VPConfig): JarmSpec? =
            JarmOption.make(clientMetaData, walletOpenId4VPConfig)?.let { jarmOption ->
                val holderId = walletOpenId4VPConfig.decentralizedIdentifier
                JarmSpec(holderId, jarmOption)
            }
    }
}
