/*
 * Copyright (c) 2023 European Commission
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package eu.europa.ec.eudi.openid4vp

import eu.europa.ec.eudi.openid4vp.ResolvedRequestObject.*
import eu.europa.ec.eudi.openid4vp.internal.response.DefaultAuthorizationResponseBuilder
import eu.europa.ec.eudi.prex.Claim
import eu.europa.ec.eudi.prex.PresentationSubmission
import java.io.Serializable
import java.net.URI
import java.net.URL

/**
 * The payload of an [AuthorizationResponse]
 */
sealed interface AuthorizationResponsePayload : Serializable {

    val state: String

    sealed interface Success : AuthorizationResponsePayload

    /**
     * In response to a [ResolvedRequestObject.SiopAuthentication]
     * and holder's [Consensus.PositiveConsensus.IdTokenConsensus]
     *
     * @param idToken The id_token produced by the wallet
     * @param state the state of the [request][ResolvedRequestObject.SiopAuthentication.state]
     */
    data class SiopAuthenticationResponse(
        val idToken: Jwt,
        override val state: String,
    ) : Success

    /**
     * In response to a [ResolvedRequestObject.OpenId4VPAuthorization]
     * and holder's [Consensus.PositiveConsensus.VPTokenConsensus]
     *
     * @param verifiableCredential the list of verifiable credentials
     * that fulfil the [ResolvedRequestObject.OpenId4VPAuthorization.presentationDefinition]
     * @param presentationSubmission the presentation submission
     * that fulfil the [ResolvedRequestObject.OpenId4VPAuthorization.presentationDefinition]
     * @param state the state of the [ request][ResolvedRequestObject.OpenId4VPAuthorization.state]
     */
    data class OpenId4VPAuthorizationResponse(
        val verifiableCredential: List<Jwt>,
        val presentationSubmission: PresentationSubmission,
        override val state: String,
    ) : Success

    /**
     * In response to a [ResolvedRequestObject.SiopOpenId4VPAuthentication]
     * and holder's [Consensus.PositiveConsensus.IdAndVPTokenConsensus]
     *
     * @param idToken The id_token produced by the wallet
     * @param verifiableCredential the list of verifiable credentials
     * that fulfil the [ResolvedRequestObject.SiopOpenId4VPAuthentication.presentationDefinition]
     * @param presentationSubmission the presentation submission
     *  that fulfil the [ResolvedRequestObject.SiopOpenId4VPAuthentication.presentationDefinition]
     * @param state the state of the [request][ResolvedRequestObject.SiopOpenId4VPAuthentication.state]
     */
    data class SiopOpenId4VPAuthenticationResponse(
        val idToken: Jwt,
        val verifiableCredential: List<Jwt>,
        val presentationSubmission: PresentationSubmission,
        override val state: String,
    ) : Success

    sealed interface Failed : AuthorizationResponsePayload

    /**
     * In response of an [Resolution.Invalid] [AuthorizationRequest]
     * @param error the cause
     * @param state the state of the request
     */
    data class InvalidRequest(
        val error: AuthorizationRequestError,
        override val state: String,
    ) : Failed

    /**
     * In response of a [ResolvedRequestObject] and
     * holder's [negative consensus][Consensus.NegativeConsensus]
     * @param state the state of the [request][ResolvedRequestObject.state]
     */
    data class NoConsensusResponseData(
        override val state: String,
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
         *
         * @param idToken The id_token produced by the wallet
         */
        data class IdTokenConsensus(
            val idToken: Jwt,
        ) : PositiveConsensus

        /**
         * In response to a [OpenId4VPAuthorization] where the
         * wallet has claims that fulfill Verifier's presentation definition
         * and holder has chosen the [claims to include][approvedClaims]
         */
        data class VPTokenConsensus(
            val approvedClaims: List<Claim>,
        ) : PositiveConsensus

        /**
         * In response to a [SiopOpenId4VPAuthentication]
         *
         * @param idToken The id_token produced by the wallet
         */
        data class IdAndVPTokenConsensus(
            val idToken: Jwt,
            val approvedClaims: List<Claim>,
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
    sealed interface DirectPostResponse : AuthorizationResponse {
        val responseUri: URL
    }

    /**
     * An authorization response to be communicated to verifier/RP via direct_post method
     *
     * @param responseUri the verifier/RP URI where the response will be posted
     * @param data the contents of the authorization request
     */
    data class DirectPost(override val responseUri: URL, val data: AuthorizationResponsePayload) : DirectPostResponse

    /**
     * An authorization response to be communicated to verifier/RP via direct_post.jwt method
     *
     * @param responseUri the verifier/RP URI where the response will be posted
     * @param data the contents of the authorization request
     */
    data class DirectPostJwt(override val responseUri: URL, val data: AuthorizationResponsePayload) : DirectPostResponse

    /**
     * An authorization response to be communicated via
     * a redirect to verifier's (RP) URI
     */
    sealed interface RedirectResponse : AuthorizationResponse {
        val redirectUri: URI
    }

    data class Query(override val redirectUri: URI, val data: AuthorizationResponsePayload) : RedirectResponse
    data class QueryJwt(override val redirectUri: URI, val data: AuthorizationResponsePayload) : RedirectResponse

    data class Fragment(override val redirectUri: URI, val data: AuthorizationResponsePayload) : RedirectResponse
    data class FragmentJwt(override val redirectUri: URI, val data: AuthorizationResponsePayload) : RedirectResponse
}

/**
 * An interface for building the [AuthorizationResponse]
 */
fun interface AuthorizationResponseBuilder {

    /**
     * Creates an [AuthorizationResponse] given a request and a consensus
     *
     * @param requestObject the authorization request for which the response will be created
     * @param consensus the consensus of the wallet
     */
    suspend fun build(requestObject: ResolvedRequestObject, consensus: Consensus): AuthorizationResponse

    companion object {
        /**
         * Default implementation of [AuthorizationResponseBuilder]
         */
        val Default: AuthorizationResponseBuilder = DefaultAuthorizationResponseBuilder
    }
}
