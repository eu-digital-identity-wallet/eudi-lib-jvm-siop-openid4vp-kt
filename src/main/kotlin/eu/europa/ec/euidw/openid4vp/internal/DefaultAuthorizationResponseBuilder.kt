package eu.europa.ec.euidw.openid4vp.internal

import eu.europa.ec.euidw.openid4vp.*

internal class DefaultAuthorizationResponseBuilder : AuthorizationResponseBuilder {

    override suspend fun buildResponse(
        requestObject: ResolvedRequestObject.SiopAuthentication,
        consensus: Consensus.PositiveConsensus.IdTokenConsensus
    ): AuthorizationResponse {
        val payload = AuthorizationResponsePayload.SiopAuthenticationResponse(consensus.idToken, requestObject.state)
        return toAuthorizationResponse(requestObject.responseMode, payload)
    }

    override suspend fun buildResponse(
        requestObject: ResolvedRequestObject.OpenId4VPAuthorization,
        consensus: Consensus.PositiveConsensus.VPTokenConsensus
    ): AuthorizationResponse {
        TODO("Not yet implemented")
    }
    override suspend fun buildResponse(
        requestObject: ResolvedRequestObject.SiopOpenId4VPAuthentication,
        consensus: Consensus.PositiveConsensus.IdAndVPTokenConsensus
    ): AuthorizationResponse {
        TODO("Not yet implemented")
    }

    private fun toAuthorizationResponse(
        responseMode: ResponseMode,
        responseData: AuthorizationResponsePayload
    ): AuthorizationResponse {
        return when (responseMode) {
            is ResponseMode.DirectPost -> AuthorizationResponse.DirectPost(responseMode.responseURI, responseData)
            is ResponseMode.DirectPostJwt -> AuthorizationResponse.DirectPostJwt(responseMode.responseURI, responseData)
            is ResponseMode.Fragment -> AuthorizationResponse.Fragment(responseMode.redirectUri, responseData)
            is ResponseMode.FragmentJwt -> AuthorizationResponse.FragmentJwt(responseMode.redirectUri, responseData)
            is ResponseMode.Query -> AuthorizationResponse.Query(responseMode.redirectUri, responseData)
            is ResponseMode.QueryJwt -> AuthorizationResponse.QueryJwt(responseMode.redirectUri, responseData)
        }
    }


}