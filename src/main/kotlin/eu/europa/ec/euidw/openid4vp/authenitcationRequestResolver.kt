package eu.europa.ec.euidw.openid4vp

import com.eygraber.uri.Uri
import com.nimbusds.openid.connect.sdk.rp.OIDCClientMetadata
import eu.europa.ec.euidw.openid4vp.AuthorizationRequest.JwtSecured.PassByReference
import eu.europa.ec.euidw.openid4vp.AuthorizationRequest.JwtSecured.PassByValue
import eu.europa.ec.euidw.openid4vp.internal.AuthorizationRequestResolverImpl
import eu.europa.ec.euidw.openid4vp.internal.utils.HttpsUrl
import eu.europa.ec.euidw.prex.PresentationDefinition
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.jsonObject

sealed interface AuthorizationRequest {

    data class NotSecured(val data: RequestObject) : AuthorizationRequest

    sealed interface JwtSecured : AuthorizationRequest {
        val clientId: String

        data class PassByValue(override val clientId: String, val jwt: Jwt) : JwtSecured
        data class PassByReference(override val clientId: String, val jwtURI: HttpsUrl) : JwtSecured
    }

    companion object {

        private val json: Json = Json

        fun make(uriStr: String): Result<AuthorizationRequest> = runCatching {
            val uri = Uri.parse(uriStr)
            fun clientId(): String = uri.getQueryParameter("client_id")
                ?: throw RequestValidationError.MissingClientId.asException()

            val requestValue = uri.getQueryParameter("request")
            val requestUriValue = uri.getQueryParameter("request_uri")

            when {
                !requestValue.isNullOrEmpty() -> PassByValue(clientId(), requestValue)
                !requestUriValue.isNullOrEmpty() -> HttpsUrl.make(requestUriValue)
                    .map { PassByReference(clientId(), it) }.getOrThrow()

                else -> makeOauth2(uri)
            }
        }

        private fun makeOauth2(uri: Uri): NotSecured {

            fun jsonObject(p: String): JsonObject? =
                uri.getQueryParameter(p)?.let { json.parseToJsonElement(it).jsonObject }

            return NotSecured(
                RequestObject(
                    responseType = uri.getQueryParameter("response_type"),
                    presentationDefinition = jsonObject("presentation_definition"),
                    presentationDefinitionUri = uri.getQueryParameter("presentation_definition_uri"),
                    scope = uri.getQueryParameter("scope"),
                    nonce = uri.getQueryParameter("nonce"),
                    responseMode = uri.getQueryParameter("response_mode"),
                    clientIdScheme = uri.getQueryParameter("client_id_scheme"),
                    clientMetaData = jsonObject("client_metadata"),
                    clientId = uri.getQueryParameter("client_id"),
                    responseUri = uri.getQueryParameter("response_uri"),
                    redirectUri = uri.getQueryParameter("redirect_uri"),
                    state = uri.getQueryParameter("state")
                )
            )
        }
    }

}

sealed interface ResolvedRequestObject {

    data class IdTokenRequestObject(
        val idTokenType: List<IdTokenType>,
        val clientMetaData: OIDCClientMetadata,
        val clientId: String,
        val nonce: String,
        val responseMode: ResponseMode,
        val state: String,
        val scope: Scope
    ) : ResolvedRequestObject

    data class VpTokenRequestObject(

        val presentationDefinition: PresentationDefinition,
        val clientMetaData: OIDCClientMetadata,
        val clientId: String,
        val nonce: String,
        val responseMode: ResponseMode,
        val state: String,
    ) : ResolvedRequestObject

    data class IdAndVPTokenRequestObject(
        val idTokenType: List<IdTokenType>,
        val presentationDefinition: PresentationDefinition,
        val clientMetaData: OIDCClientMetadata,
        val clientId: String,
        val nonce: String,
        val responseMode: ResponseMode,
        val state: String,
        val scope: Scope
    ) : ResolvedRequestObject
}

interface AuthorizationRequestResolver {
    suspend fun resolveRequest(
        uriStr: String
    ): Result<ResolvedRequestObject> = runCatching {
        val request = AuthorizationRequest.make(uriStr).getOrThrow()
        resolveRequest(request).getOrThrow()
    }

    suspend fun resolveRequest(
        request: AuthorizationRequest
    ): Result<ResolvedRequestObject>

    companion object {
        fun make(walletOpenId4VPConfig: WalletOpenId4VPConfig): AuthorizationRequestResolver =
            AuthorizationRequestResolverImpl(walletOpenId4VPConfig)
    }
}