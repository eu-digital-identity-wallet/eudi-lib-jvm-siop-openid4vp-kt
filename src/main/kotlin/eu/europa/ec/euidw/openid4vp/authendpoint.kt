package eu.europa.ec.euidw.openid4vp

import com.eygraber.uri.Uri
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.jsonObject
import java.net.URL
import java.net.URLDecoder


sealed interface AuthorizationRequest {

    data class Oauth2(val data: AuthorizationRequestData): AuthorizationRequest

    sealed interface JwtSecuredAuthorizationRequest : AuthorizationRequest {
        data class PassByValue(val jwt: String): JwtSecuredAuthorizationRequest
        data class PassByReference(val jwtURI: HttpsUrl): JwtSecuredAuthorizationRequest
    }

    companion object {

        private val json: Json by lazy { Json }
        fun make(uriStr: String): Result<AuthorizationRequest> = runCatching {
            val uri = Uri.parse(uriStr)
            when {
                uri.getQueryParameter("request") != null -> TODO()
                uri.getQueryParameter("request_uri") != null -> TODO()
                else -> makeOauth2(uri).getOrThrow()
            }
        }

        private fun makeOauth2(uri: Uri): Result<Oauth2> = runCatching {

            Oauth2(
                AuthorizationRequestData(
                    responseType = uri.getQueryParameter("response_type"),
                    presentationDefinition = uri.getQueryParameter("presentation_definition"),
                    presentationDefinitionUri = uri.getQueryParameter("presentation_definition_uri"),
                    scope = uri.getQueryParameter("scope"),
                    nonce = uri.getQueryParameter("nonce"),
                    responseMode = uri.getQueryParameter("response_mode"),
                    clientIdScheme = uri.getQueryParameter("client_id_scheme"),
                    clientMetaData = uri.getQueryParameter("client_metadata"),
                    clientId = uri.getQueryParameter("client_id")
                ))
        }
    }
}

typealias Jwt = String

interface AuthorizationResponseData

sealed interface AuthorizationResponse {

    sealed interface Success : AuthorizationResponse

    data class DirectPost(val url: HttpsUrl, val data: AuthorizationResponseData): Success
    data class DirectPostJwt(val url: HttpsUrl, val string: Jwt): Success


    sealed interface Failed: AuthorizationResponse
    data class Invalid(val error: AuthorizationRequestValidationError): Failed
}



interface OpenId4VPAuthorizationEndPoint {


    fun authorize(url: String): AuthorizationResponse {
       return  authorize(AuthorizationRequest.make(url).getOrThrow())
    }

    fun authorize(auth: AuthorizationRequest): AuthorizationResponse {
        return when(auth){
            is AuthorizationRequest.Oauth2 -> authorize(auth.data)
                .fold(onFailure = {t->
                                  if (t is AuthorizationRequestValidationException) {
                                      AuthorizationResponse.Invalid(t.error)
                                  } else throw t
                }, onSuccess = {data->
                    val url: HttpsUrl = TODO()
                    AuthorizationResponse.DirectPost(url, data)
                })
            else -> throw IllegalArgumentException("Not supported")
        }
    }


    fun AuthorizationResponseData.asJwt(): Jwt


    fun authorize(requestData: AuthorizationRequestData) : Result<AuthorizationResponseData>{
        TODO()
    }
}

