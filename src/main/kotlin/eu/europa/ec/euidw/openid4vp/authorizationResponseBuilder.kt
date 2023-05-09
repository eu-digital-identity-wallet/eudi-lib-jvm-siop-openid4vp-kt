package eu.europa.ec.euidw.openid4vp

import com.nimbusds.jwt.JWT
import eu.europa.ec.euidw.openid4vp.internal.DefaultAuthorizationResponseBuilder
import eu.europa.ec.euidw.prex.PresentationSubmission

sealed interface AuthorizationResponse {

    sealed interface Success : AuthorizationResponse

    data class DirectPost(val url: HttpsUrl, val data: AuthorizationResponseData, val state : String) : Success
    data class DirectPostJwt(val url: HttpsUrl, val string: Jwt, val state : String) : Success


    sealed interface Failed : AuthorizationResponse
    data class InvalidRequest(val error: RequestValidationError, val state : String) : Failed

    data class FailedToResolveRequest(val error: ResolutionError, val state : String) : Failed
    data class InvalidUrl(val url: String, val state : String) : Failed
    data class UserRejection(val rejectionMessage: String, val state : String) : Failed
}


sealed interface AuthorizationResponseData {
    data class IdTokenResponseData(
        val idToken: JWT
    ) : AuthorizationResponseData

    data class VPTokenResponseData(
        val verifiableCredential: List<Jwt>,
        val presentationSubmission: PresentationSubmission
    ) : AuthorizationResponseData

    data class IdAndVPTokenResponseData(
        val idToken: JWT,
        val verifiableCredential: List<Jwt>,
        val presentationSubmission: PresentationSubmission
    ) : AuthorizationResponseData

    data class NoConsensusResponseData(
        val reason: String
    ) : AuthorizationResponseData

}


interface AuthorizationResponseBuilder {

    suspend fun buildResponse(
        requestObject: ResolvedRequestObject,
        consensus: Consensus
    ): AuthorizationResponse

    companion object {
        fun make(walletOpenId4VPConfig: WalletOpenId4VPConfig): AuthorizationResponseBuilder =
            DefaultAuthorizationResponseBuilder(walletOpenId4VPConfig)
    }
}

