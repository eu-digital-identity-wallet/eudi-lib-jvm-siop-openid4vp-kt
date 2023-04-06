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
            val requestValue = uri.getQueryParameter("request")
            val requestUriValue = uri.getQueryParameter("request_uri")

            when {
                !requestValue.isNullOrEmpty() -> JwtSecuredAuthorizationRequest.PassByValue(requestValue)
                !requestUriValue.isNullOrEmpty()-> HttpsUrl.make(requestUriValue).map { JwtSecuredAuthorizationRequest.PassByReference(it) }.getOrThrow()
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
    data class InvalidRequest(val error: AuthorizationRequestValidationError) : Failed
    data class FailedToResolveRequest(val error: ResolutionError) : Failed
    data class InvalidUrl(val url: String) : Failed
}


interface OpenId4VPAuthorizationEndPoint {

    suspend fun authorize(url: String): AuthorizationResponse {
        return when (val request = AuthorizationRequest.make(uriStr = url).getOrNull()) {
            null -> AuthorizationResponse.InvalidUrl(url)
            else -> authorize(request)
        }
    }

    suspend fun authorize(request: AuthorizationRequest): AuthorizationResponse

}

internal class DefaultOpenId4VPAuthorizationEndPoint(
    private val validator: AuthorizationRequestValidator,
    private val resolver: AuthorizationRequestResolver
) : OpenId4VPAuthorizationEndPoint {

    override suspend fun authorize(request: AuthorizationRequest): AuthorizationResponse {
        return runCatching {
            val unvalidated = data(request).getOrThrow()
            val validated = validate(unvalidated).getOrThrow()
            val resolved = resolve(validated).getOrThrow()
            authorize(resolved)
        }.fold({ it }, onFailure = { failureOf(it) ?: throw it })

    }


    private suspend fun authorize(request: ResolvedOpenID4VPRequestData): AuthorizationResponse {
        TODO()
    }

    private fun failureOf(t: Throwable): AuthorizationResponse? = when (t) {
        is AuthorizationRequestValidationException -> AuthorizationResponse.InvalidRequest(t.error)
        is ResolutionException -> AuthorizationResponse.FailedToResolveRequest(t.error)
        else -> null
    }

    private suspend fun data(request: AuthorizationRequest): Result<OpenID4VPRequestData> = when (request) {
        is AuthorizationRequest.Oauth2 -> request.data.success()
        is AuthorizationRequest.JwtSecuredAuthorizationRequest.PassByValue -> fromJwt(request.jwt)
        is AuthorizationRequest.JwtSecuredAuthorizationRequest.PassByReference -> fetch(request.jwtURI)
    }

    private fun fromJwt(jwt: Jwt): Result<OpenID4VPRequestData> = TODO()
    private suspend fun fetch(uri: HttpsUrl): Result<OpenID4VPRequestData> = TODO()

    private fun validate(unvalidated: OpenID4VPRequestData): Result<ValidatedOpenID4VPRequestData> =
        validator.validate(unvalidated)

    private suspend fun resolve(validated: ValidatedOpenID4VPRequestData): Result<ResolvedOpenID4VPRequestData> =
        resolver.resolve(validated)


}

