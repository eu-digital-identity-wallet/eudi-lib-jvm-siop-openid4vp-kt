package eu.europa.ec.euidw.openid4vp.internal.dispatch

import eu.europa.ec.euidw.openid4vp.AuthorizationResponse
import eu.europa.ec.euidw.openid4vp.AuthorizationResponsePayload
import eu.europa.ec.euidw.openid4vp.HttpFormPost

internal class DirectPostResponseDispatcher(
    val httpFormPost : HttpFormPost
) {

    suspend fun dispatch(response : AuthorizationResponse.DirectPost) : String {
        val formParameters = response.data.asFormParameters()
        return httpFormPost.post(response.responseUri.value, formParameters)
    }

    fun dispatch(response : AuthorizationResponse.DirectPostJwt) : String {
        TODO()
    }

    private fun AuthorizationResponsePayload.asFormParameters() : Map<String, String> {
        when (this) {
            is AuthorizationResponsePayload.SiopOpenId4VPAuthenticationResponse -> TODO()
            is AuthorizationResponsePayload.SiopAuthenticationResponse -> TODO()
            is AuthorizationResponsePayload.OpenId4VPAuthorizationResponse -> TODO()

            is AuthorizationResponsePayload.InvalidRequest -> TODO()
            is AuthorizationResponsePayload.NoConsensusResponseData -> TODO()
        }
    }

}