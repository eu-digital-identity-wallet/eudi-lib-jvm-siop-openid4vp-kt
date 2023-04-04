package eu.europa.ec.euidw.openid4vp

import com.eygraber.uri.Uri
import kotlinx.serialization.json.Json


sealed interface AuthorizationRequest {

    data class Oauth2(val data: OpenID4VPRequestData) : AuthorizationRequest

    sealed interface JwtSecuredAuthorizationRequest : AuthorizationRequest {
        data class PassByValue(val jwt: Jwt) : JwtSecuredAuthorizationRequest
        data class PassByReference(val jwtURI: HttpsUrl) : JwtSecuredAuthorizationRequest
    }

    companion object {

        private val json: Json by lazy { Json }
        fun make(uriStr: String): Result<AuthorizationRequest> = runCatching {
            val uri = Uri.parse(uriStr)
            when {
                uri.getQueryParameter("request") != null -> TODO()
                uri.getQueryParameter("request_uri") != null -> TODO()
                else -> makeOauth2(uri)
            }
        }

        private fun makeOauth2(uri: Uri): Oauth2 =
            Oauth2(
                OpenID4VPRequestData(
                    responseType = uri.getQueryParameter("response_type"),
                    presentationDefinition = uri.getQueryParameter("presentation_definition"),
                    presentationDefinitionUri = uri.getQueryParameter("presentation_definition_uri"),
                    scope = uri.getQueryParameter("scope"),
                    nonce = uri.getQueryParameter("nonce"),
                    responseMode = uri.getQueryParameter("response_mode"),
                    clientIdScheme = uri.getQueryParameter("client_id_scheme"),
                    clientMetaData = uri.getQueryParameter("client_metadata"),
                    clientId = uri.getQueryParameter("client_id"),
                    responseUri = uri.getQueryParameter("response_uri"),
                    redirectUri = uri.getQueryParameter("redirect_uri"),
                    state = uri.getQueryParameter("state")
                )
            )
    }

}

typealias Jwt = String

interface AuthorizationResponseData

sealed interface AuthorizationResponse {

    sealed interface Success : AuthorizationResponse

    data class DirectPost(val url: HttpsUrl, val data: AuthorizationResponseData) : Success
    data class DirectPostJwt(val url: HttpsUrl, val string: Jwt) : Success


    sealed interface Failed : AuthorizationResponse
    data class Invalid(val error: AuthorizationRequestValidationError) : Failed
}


interface OpenId4VPAuthorizationEndPoint {


    fun authorize(url: String): AuthorizationResponse

}

