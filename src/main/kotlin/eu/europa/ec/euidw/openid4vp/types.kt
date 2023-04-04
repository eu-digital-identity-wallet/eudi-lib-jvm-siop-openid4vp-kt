package eu.europa.ec.euidw.openid4vp

import eu.europa.ec.euidw.prex.PresentationDefinition
import kotlinx.serialization.json.JsonObject
import java.net.URL

/**
 * Represents an HTTPS URL
 */
@JvmInline
value class HttpsUrl private constructor(val value: URL) {
    init {
        require("https" == value.protocol) { "Only https is supported" }
    }

    companion object {
        fun make(s: String): Result<HttpsUrl> = runCatching { HttpsUrl(URL(s)) }
        fun make(url: URL): Result<HttpsUrl> = runCatching { HttpsUrl(url) }
    }
}


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
    data class Scopes(val scopes: List<String>) : PresentationDefinitionSource
}

typealias ClientMetaData = JsonObject

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

    DID;

    companion object {

        fun make(s: String): ClientIdScheme? = when (s) {
            "pre-registered" -> PreRegistered
            "redirect_uri" -> RedirectUri
            "entity_id" -> EntityId
            "did" -> DID
            else -> null
        }
    }

}


sealed interface ResponseMode {
    object Fragment : ResponseMode
    data class DirectPost(val responseURI: HttpsUrl) : ResponseMode
}


enum class ResponseType {
    VpToken,// VP in AuthorizationResponse
    IdToken, // Initiates SIOP
    Code, // VP via  Token end point
    VpAndIdToken // VP in AuthorizationResponse
}

@JvmInline
value class Scope(val value: String)
typealias Nonce = String


data class AuthorizationRequestData(
    val responseType: String? = null,
    val presentationDefinition: String? = null,
    val presentationDefinitionUri: String? = null,
    val clientMetaData: String? = null,
    val clientMetadataUri: String? = null,
    val clientIdScheme: String? = null,
    val clientId: String? = null,
    val nonce: String?,
    val scope: String? = null,
    val responseMode: String? = null,
    val state: String? = null
)

data class ValidatedAuthorizationRequestData(
    val responseType: ResponseType,
    val presentationDefinitionSource: PresentationDefinitionSource? = null,
    val clientMetaDataSource: ClientMetaDataSource? = null,
    val clientIdScheme: ClientIdScheme? = null,
    val nonce: Nonce,
    val scope: Scope?,
    val responseMode: ResponseMode = ResponseMode.Fragment,
    val state: String?
)

data class ResolvedAuthorizationRequestData(
    val presentationDefinition: PresentationDefinition,
    val clientMetaData: ClientMetaData? = null,
    val nonce: Nonce,
    val responseMode: ResponseMode = ResponseMode.Fragment
)