package eu.europa.ec.euidw.openid4vp.internal.dispatch

import eu.europa.ec.euidw.openid4vp.AuthorizationResponse
import eu.europa.ec.euidw.openid4vp.AuthorizationResponseData
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

    private fun AuthorizationResponseData.asFormParameters() : Map<String, String> {
        when (this) {
            is AuthorizationResponseData.IdAndVPTokenResponseData -> TODO()
            is AuthorizationResponseData.IdTokenResponseData -> TODO()
            is AuthorizationResponseData.VPTokenResponseData -> TODO()

            is AuthorizationResponseData.FailedToResolveRequest -> TODO()
            is AuthorizationResponseData.InvalidRequest -> TODO()
            is AuthorizationResponseData.InvalidUrl -> TODO()
            is AuthorizationResponseData.NoConsensusResponseData -> TODO()
            is AuthorizationResponseData.UserRejection -> TODO()
        }
    }

}