package eu.europa.ec.euidw.openid4vp

import eu.europa.ec.euidw.openid4vp.internal.utils.HttpsUrl
import eu.europa.ec.euidw.prex.Claim
import eu.europa.ec.euidw.prex.PresentationDefinition
import kotlinx.serialization.Required
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

sealed interface PresentationDefinitionSource {

    /**
     * Presentation definition is passed by value (that is embedded to the authorization request)
     * by the verifier
     */
    data class PassByValue(val presentationDefinition: PresentationDefinition) : PresentationDefinitionSource

    /**
     * Presentation Definition can be retrieved from the resource at the specified
     * URL, rather than being passed by value.
     * The Wallet will send a GET request without additional parameters.
     * The resource MUST be exposed without further need to authenticate or authorize
     */
    data class FetchByReference(val url: HttpsUrl) : PresentationDefinitionSource
    data class Implied(val scope: Scope) : PresentationDefinitionSource
}

@Serializable
data class ClientMetaData( // By OpenID Connect Dynamic Client Registration specification
    @SerialName("jwks_uri") val jwksUri : String,
    @SerialName("id_token_signed_response_alg") val idTokenSignedResponseAlg : String,
    @SerialName("id_token_encrypted_response_alg")val idTokenEncryptedResponseAlg : String,
    @SerialName("id_token_encrypted_response_enc") val idTokenEncryptedResponseEnc: String,
    @SerialName("subject_syntax_types_supported") val subjectSyntaxTypesSupported : List<String>
)

@JvmInline
value class Scope private constructor(val value: String) {
    fun items(): List<String> = itemsOf(value)

    companion object {
        fun make(s: String): Scope? {
            val trimmed = s.trim()
            val scopeItems: List<String> = itemsOf(trimmed)
            return if (scopeItems.isEmpty()) null
            else Scope(trimmed)
        }

        private fun itemsOf(s: String): List<String> = s.split(" ")
    }
}

sealed interface ClientMetaDataSource {
    data class PassByValue(val metaData: ClientMetaData) : ClientMetaDataSource
    data class FetchByReference(val url: HttpsUrl) : ClientMetaDataSource
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

    ISO_X509;

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
sealed interface ResponseMode {

    /**
     * In this mode, Authorization Response parameters are encoded
     * in the query string added to the redirect_uri when redirecting back to the Client.
     */
    data class Query(val redirectUri: HttpsUrl) : ResponseMode

    /**
     * In this mode, Authorization Response parameters
     * are encoded in the fragment added to the redirect_uri when redirecting back to the Client.
     */
    data class Fragment(val redirectUri: HttpsUrl) : ResponseMode
    data class DirectPost(val responseURI: HttpsUrl) : ResponseMode
    data class DirectPostJwt(val responseURI: HttpsUrl) : ResponseMode
}


enum class ResponseType {
    VpToken,
    IdToken,
    VpAndIdToken
}

/**
 * The data of an OpenID4VP authorization request
 * without any validation and regardless of the way they sent to the wallet
 */
@Serializable
data class SiopId4VPRequestObject(
    @SerialName("client_metadata") val clientMetaData: String? = null,
    @SerialName("client_metadata_uri") val clientMetadataUri: String? = null,
    @SerialName("client_id_scheme") val clientIdScheme: String? = null,
    @Required val nonce: String? = null,
    @SerialName("client_id") val clientId: String? = null,
    @SerialName("response_type") val responseType: String? = null,
    @SerialName("response_mode") val responseMode: String? = null,
    @SerialName("response_uri") val responseUri: String? = null,
    @SerialName("presentation_definition") val presentationDefinition: String? = null,
    @SerialName("redirect_uri") val redirectUri: String? = null,
    val scope: String? = null,
    @SerialName("supported_algorithm") val supportedAlgorithm: String? = null,
    @SerialName("presentation_definition_uri") val presentationDefinitionUri: String? = null, // Not utilized from ISO-23330-4
    val state: String? = null, // OpenId4VP specific, not utilized from ISO-23330-4
    @SerialName("id_token_type") val idTokenType: String? = null
)

typealias Jwt = String
enum class IdTokenType {
    SubjectSigned,
    AttesterSigned
}

sealed interface Consensus {

    interface NegativeConsensus : Consensus
    sealed interface PositiveConsensus : Consensus {
        object IdTokenConsensus : PositiveConsensus

        data class VPTokenConsensus(
            val approvedClaims: List<Claim>
        ) : PositiveConsensus

        data class IdAndVPTokenConsensus(
            val approvedClaims: List<Claim>
        ) : PositiveConsensus
    }
}

sealed interface RequestConsensus {
    data class ReleaseClaims(
        val claims : List<ReleaseClaim>
    ) : RequestConsensus {
        data class ReleaseClaim(
            val claim : Claim,
            val attributes : List<String>
        )
    }

    data class ReleaseIdentity(
        val requester : String,
        val reason : String
    ) :RequestConsensus

    object NoClaims : RequestConsensus
}
