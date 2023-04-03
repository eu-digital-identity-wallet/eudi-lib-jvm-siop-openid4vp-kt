package niscy.eudiw.openid4vp

import java.net.URL


sealed interface AuthorizationRequest {

    data class Oauth2(val data: AuthorizationRequestData): AuthorizationRequest

    sealed interface JwtSecuredAuthorizationRequest : AuthorizationRequest {
        data class PassByValue(val jwt: String): JwtSecuredAuthorizationRequest
        data class PassByReference(val jwtURI: HttpsUrl): JwtSecuredAuthorizationRequest
    }

    companion object {
        fun make(url: URL): Result<AuthorizationRequest> = TODO()
    }
}

typealias Jwt = String

interface AuthorizationResponseData

sealed interface AuthorizationResponse {

    sealed interface Success :AuthorizationResponse

    data class DirectPost(val url: HttpsUrl, val data: AuthorizationResponseData): Success
    data class DirectPostJwt(val url: HttpsUrl, val string: Jwt):Success


    sealed interface Failed: AuthorizationResponse
    data class Invalid(val error: AuthorizationRequestValidationError): Failed
}



interface OpenId4VPAuthorizationEndPoint {


    fun authorize(url: URL):  AuthorizationResponse {
       return  authorize(AuthorizationRequest.make(url).getOrThrow())
    }

    fun authorize(auth: AuthorizationRequest):  AuthorizationResponse {
        return when(auth){
            is AuthorizationRequest.Oauth2-> authorize(auth.data)
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

