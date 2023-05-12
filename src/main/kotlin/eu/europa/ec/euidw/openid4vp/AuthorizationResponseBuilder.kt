package eu.europa.ec.euidw.openid4vp

import com.nimbusds.jwt.JWT
import eu.europa.ec.euidw.prex.Claim
import eu.europa.ec.euidw.prex.PresentationSubmission
import java.io.Serializable

sealed interface AuthorizationResponse : Serializable {
    sealed interface DirectPostResponse : AuthorizationResponse
    data class DirectPost(val responseUri: HttpsUrl, val data: AuthorizationResponsePayload) : DirectPostResponse
    data class DirectPostJwt(val responseUri: HttpsUrl, val data: AuthorizationResponsePayload) : DirectPostResponse

    sealed interface RedirectResponse : AuthorizationResponse
    sealed interface QueryResponse : RedirectResponse
    data class Query(val redirectUri: HttpsUrl, val data: AuthorizationResponsePayload) : QueryResponse
    data class QueryJwt(val redirectUri: HttpsUrl, val data: AuthorizationResponsePayload) : QueryResponse

    sealed interface FragmentResponse : RedirectResponse
    data class Fragment(val redirectUri: HttpsUrl, val data: AuthorizationResponsePayload) : FragmentResponse
    data class FragmentJwt(val redirectUri: HttpsUrl, val data: AuthorizationResponsePayload) : FragmentResponse
}


sealed interface AuthorizationResponsePayload : Serializable {

    val state: String

    sealed interface Success : AuthorizationResponsePayload

    data class SiopAuthenticationResponse(
        val idToken: JWT,
        override val state: String
    ) : Success

    data class OpenId4VPAuthorizationResponse(
        val verifiableCredential: List<Jwt>,
        val presentationSubmission: PresentationSubmission,
        override val state: String
    ) : Success

    data class SiopOpenId4VPAuthenticationResponse(
        val idToken: JWT,
        val verifiableCredential: List<Jwt>,
        val presentationSubmission: PresentationSubmission,
        override val state: String
    ) : Success

    sealed interface Failed : AuthorizationResponsePayload
    data class InvalidRequest(
        val error: AuthorizationRequestError,
        override val state: String
    ) : Failed

    data class NoConsensusResponseData(
        val reason: String?,
        override val state: String
    ) : Failed
}

sealed interface Consensus : Serializable {

    interface NegativeConsensus : Consensus
    sealed interface PositiveConsensus : Consensus {
        data class IdTokenConsensus(
            val idToken: JWT
        ) : PositiveConsensus

        data class VPTokenConsensus(
            val approvedClaims: List<Claim>
        ) : PositiveConsensus

        data class IdAndVPTokenConsensus(
            val idToken: JWT,
            val approvedClaims: List<Claim>
        ) : PositiveConsensus
    }
}

sealed interface RequestConsensus : Serializable {
    data class ReleaseClaims(
        val claims: List<ReleaseClaim>
    ) : RequestConsensus {
        data class ReleaseClaim(
            val claim: Claim,
            val attributes: List<String>
        )
    }

    data class ReleaseIdentity(
        val requester: String,
        val reason: String
    ) : RequestConsensus

    object NoClaims : RequestConsensus
}

interface AuthorizationResponseBuilder {

    suspend fun buildResponse(
        requestObject: ResolvedRequestObject.SiopAuthentication,
        consensus: Consensus.PositiveConsensus.IdTokenConsensus
    ): AuthorizationResponse

    suspend fun buildResponse(
        requestObject: ResolvedRequestObject.OpenId4VPAuthorization,
        consensus: Consensus.PositiveConsensus.VPTokenConsensus
    ): AuthorizationResponse

    suspend fun buildResponse(
        requestObject: ResolvedRequestObject.SiopOpenId4VPAuthentication,
        consensus: Consensus.PositiveConsensus.IdAndVPTokenConsensus
    ): AuthorizationResponse

    // TODO: Consider build error response

}

