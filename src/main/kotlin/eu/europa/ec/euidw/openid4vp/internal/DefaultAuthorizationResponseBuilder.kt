package eu.europa.ec.euidw.openid4vp.internal

import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.JWSHeader
import com.nimbusds.jose.crypto.RSASSASigner
import com.nimbusds.jose.jwk.JWKSet
import com.nimbusds.jose.jwk.ThumbprintUtils
import com.nimbusds.jwt.JWT
import com.nimbusds.jwt.JWTClaimsSet
import com.nimbusds.jwt.SignedJWT
import com.nimbusds.openid.connect.sdk.claims.IDTokenClaimsSet
import eu.europa.ec.euidw.openid4vp.*
import java.time.LocalDateTime
import java.time.ZoneId
import java.util.*

internal class DefaultAuthorizationResponseBuilder : AuthorizationResponseBuilder {

    override suspend fun buildResponse(
        request: ResolvedRequestObject.SiopAuthentication,
        consensus: Consensus.PositiveConsensus.IdTokenConsensus
    ): AuthorizationResponse {
        val payload = AuthorizationResponsePayload.SiopAuthenticationResponse(consensus.idToken, request.state)
        return toAuthorizationResponse(request.responseMode, payload)
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