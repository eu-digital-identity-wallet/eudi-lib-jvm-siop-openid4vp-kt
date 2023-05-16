package eu.europa.ec.euidw.openid4vp

import com.nimbusds.jwt.JWT
import eu.europa.ec.euidw.openid4vp.Consensus.NegativeConsensus
import eu.europa.ec.euidw.openid4vp.Consensus.PositiveConsensus
import eu.europa.ec.euidw.openid4vp.ResolvedRequestObject.*
import eu.europa.ec.euidw.openid4vp.internal.response.DefaultAuthorizationResponseBuilder
import eu.europa.ec.euidw.prex.Claim
import eu.europa.ec.euidw.prex.PresentationSubmission
import java.io.Serializable

/**
 * The payload of an [AuthorizationResponse]
 */
sealed interface AuthorizationResponsePayload : Serializable {

    val state: String

    sealed interface Success : AuthorizationResponsePayload

    /**
     * In response to a [ResolvedRequestObject.SiopAuthentication]
     * and holder's [Consensus.PositiveConsensus.IdTokenConsensus]
     */
    data class SiopAuthenticationResponse(
        val idToken: Jwt,
        override val state: String
    ) : Success

    /**
     * In response to a [ResolvedRequestObject.OpenId4VPAuthorization]
     * and holder's [Consensus.PositiveConsensus.VPTokenConsensus]
     */
    data class OpenId4VPAuthorizationResponse(
        val verifiableCredential: List<Jwt>,
        val presentationSubmission: PresentationSubmission,
        override val state: String
    ) : Success

    /**
     * In response to a [ResolvedRequestObject.SiopOpenId4VPAuthentication]
     * and holder's [Consensus.PositiveConsensus.IdAndVPTokenConsensus]
     */
    data class SiopOpenId4VPAuthenticationResponse(
        val idToken: Jwt,
        val verifiableCredential: List<Jwt>,
        val presentationSubmission: PresentationSubmission,
        override val state: String
    ) : Success

    sealed interface Failed : AuthorizationResponsePayload

    /**
     * In response of an [Resolution.Invalid] [AuthorizationRequest]
     */
    data class InvalidRequest(
        val error: AuthorizationRequestError,
        override val state: String
    ) : Failed

    /**
     * In response of a [ResolvedRequestObject] and
     * holder's [negative consensus][Consensus.NegativeConsensus]
     */
    data class NoConsensusResponseData(
        val reason: String?,
        override val state: String
    ) : Failed
}

/**
 * Representation of holder's consensus to
 * a [ResolvedRequestObject]
 */
sealed interface Consensus : Serializable {

    /**
     * No consensus. Holder decided to reject
     * the request
     */
    object NegativeConsensus : Consensus {
        override fun toString(): String = "NegativeConsensus"
    }

    /**
     * Positive consensus. Holder decided to
     * respond the request
     */
    sealed interface PositiveConsensus : Consensus {
        /**
         * In response to a [SiopAuthentication]
         * Holder/Wallet provides a [idToken] JWT
         */
        data class IdTokenConsensus(
            val idToken: Jwt
        ) : PositiveConsensus

        /**
         * In response to a [OpenId4VPAuthorization] where the
         * wallet has claims that fulfill Verifier's presentation definition
         * and holder has chosen the [claims to include][approvedClaims]
         */
        data class VPTokenConsensus(
            val approvedClaims: List<Claim>
        ) : PositiveConsensus

        /**
         * In response to a [SiopOpenId4VPAuthentication]
         */
        data class IdAndVPTokenConsensus(
            val idToken: Jwt,
            val approvedClaims: List<Claim>
        ) : PositiveConsensus
    }
}



/**
 * An OAUTH2 authorization response
 */
sealed interface AuthorizationResponse : Serializable {
    /**
     * An authorization response to be communicated via either
     * direct_post or direct_pst.jwt
     */
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

interface AuthorizationResponseBuilder {

    suspend fun build(
        requestObject: ResolvedRequestObject,
        consensus: Consensus
    ): AuthorizationResponse =

        if (consensus is NegativeConsensus) buildNoConsensusResponse(requestObject)
        else when (requestObject) {
            is SiopAuthentication -> when (consensus) {
                is PositiveConsensus.IdTokenConsensus -> buildResponse(requestObject, consensus)
                else -> error("Unexpected consensus")
            }

            is OpenId4VPAuthorization -> when (consensus) {
                is PositiveConsensus.VPTokenConsensus -> buildResponse(requestObject, consensus)
                else -> error("Unexpected consensus")
            }

            is SiopOpenId4VPAuthentication -> when (consensus) {
                is PositiveConsensus.IdAndVPTokenConsensus -> buildResponse(requestObject, consensus)
                else -> error("Unexpected consensus")
            }
        }


    suspend fun buildResponse(
        requestObject: SiopAuthentication,
        consensus: PositiveConsensus.IdTokenConsensus
    ): AuthorizationResponse

    suspend fun buildResponse(
        requestObject: OpenId4VPAuthorization,
        consensus: PositiveConsensus.VPTokenConsensus
    ): AuthorizationResponse

    suspend fun buildResponse(
        requestObject: SiopOpenId4VPAuthentication,
        consensus: PositiveConsensus.IdAndVPTokenConsensus
    ): AuthorizationResponse

    suspend fun buildNoConsensusResponse(requestObject: ResolvedRequestObject): AuthorizationResponse {
        TODO("buildNoConsensusResponse")
    }

    companion object {
        val Default: AuthorizationResponseBuilder = DefaultAuthorizationResponseBuilder
    }
}

