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

import com.nimbusds.jose.JWSSigner
import eu.europa.ec.eudi.openid4vp.ResolvedRequestObject.*
import eu.europa.ec.eudi.prex.PresentationSubmission
import java.io.Serializable
import java.net.URI
import java.net.URL

/**
 * The payload of an [AuthorizationResponse]
 */
sealed interface AuthorizationResponsePayload : Serializable {

    val state: String
    val clientId: String

    sealed interface Success : AuthorizationResponsePayload

    /**
     * In response to a [ResolvedRequestObject.SiopAuthentication]
     * and holder's [Consensus.PositiveConsensus.IdTokenConsensus]
     *
     * @param idToken The id_token produced by the wallet
     * @param state the state of the [request][ResolvedRequestObject.SiopAuthentication.state]
     */
    data class SiopAuthentication(
        val idToken: Jwt,
        override val state: String,
        override val clientId: String,
    ) : Success

    /**
     * In response to a [ResolvedRequestObject.OpenId4VPAuthorization]
     * and holder's [Consensus.PositiveConsensus.VPTokenConsensus]
     *
     * @param vpToken the vp_token
     * that fulfils the [ResolvedRequestObject.OpenId4VPAuthorization.presentationDefinition]
     * @param presentationSubmission the presentation submission
     * that fulfils the [ResolvedRequestObject.OpenId4VPAuthorization.presentationDefinition]
     * @param state the state of the [ request][ResolvedRequestObject.OpenId4VPAuthorization.state]
     */
    data class OpenId4VPAuthorization(
        val vpToken: VpToken,
        val presentationSubmission: PresentationSubmission,
        override val state: String,
        override val clientId: String,
    ) : Success

    /**
     * In response to a [ResolvedRequestObject.SiopOpenId4VPAuthentication]
     * and holder's [Consensus.PositiveConsensus.IdAndVPTokenConsensus]
     *
     * @param idToken The id_token produced by the wallet
     * @param vpToken the vp_token
     *       that fulfils the [ResolvedRequestObject.SiopOpenId4VPAuthentication.presentationDefinition]
     * @param presentationSubmission the presentation submission
     *  that fulfil the [ResolvedRequestObject.SiopOpenId4VPAuthentication.presentationDefinition]
     * @param state the state of the [request][ResolvedRequestObject.SiopOpenId4VPAuthentication.state]
     */
    data class SiopOpenId4VPAuthentication(
        val idToken: Jwt,
        val vpToken: VpToken,
        val presentationSubmission: PresentationSubmission,
        override val state: String,
        override val clientId: String,
    ) : Success

    sealed interface Failed : AuthorizationResponsePayload

    /**
     * In response of an [Resolution.Invalid] authorization request
     * @param error the cause
     * @param state the state of the request
     */
    data class InvalidRequest(
        val error: AuthorizationRequestError,
        override val state: String,
        override val clientId: String,
    ) : Failed

    /**
     * In response of a [ResolvedRequestObject] and
     * holder's [negative consensus][Consensus.NegativeConsensus]
     * @param state the state of the [request][ResolvedRequestObject.state]
     */
    data class NoConsensusResponseData(
        override val state: String,
        override val clientId: String,
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
    data object NegativeConsensus : Consensus {
        private fun readResolve(): Any = NegativeConsensus
    }

    /**
     * Positive consensus. Holder decided to
     *  respond to the request
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
         * and holder has chosen the claims to include
         * @param vpToken the vp_token to be included in the authorization response
         * @param presentationSubmission the presentation submission to be included in the authorization response
         */
        data class VPTokenConsensus(
            val vpToken: VpToken,
            val presentationSubmission: PresentationSubmission,
        ) : PositiveConsensus

        /**
         * In response to a [SiopOpenId4VPAuthentication]
         *
         * @param idToken The id_token produced by the wallet
         * @param vpToken the vp_token to be included in the authorization response
         * @param presentationSubmission the presentation submission to be included in the authorization response
         */
        data class IdAndVPTokenConsensus(
            val idToken: Jwt,
            val vpToken: VpToken,
            val presentationSubmission: PresentationSubmission,
        ) : PositiveConsensus
    }
}

interface AuthorizationResponseSigner : JWSSigner {
    fun getKeyId(): String
}

/**
 * An OAUTH2 authorization response
 */
sealed interface AuthorizationResponse : Serializable {

    /**
     * An authorization response to be communicated to verifier/RP via direct_post method
     *
     * @param responseUri the verifier/RP URI where the response will be posted
     * @param data the contents of the authorization response
     */
    data class DirectPost(
        val responseUri: URL,
        val data: AuthorizationResponsePayload,
    ) : AuthorizationResponse

    /**
     * An authorization response to be communicated to verifier/RP via direct_post.jwt method
     *
     * @param responseUri the verifier/RP URI where the response will be posted
     * @param data the contents of the authorization response
     * @param jarmOption the verifier/RP's requirements for JARM
     */
    data class DirectPostJwt(
        val responseUri: URL,
        val data: AuthorizationResponsePayload,
        val jarmOption: JarmOption,
    ) : AuthorizationResponse

    /**
     * An authorization response to be communicated to verifier/RP via redirect using
     * query parameters
     * @param redirectUri the verifier/RP URI where the response will be redirected to
     * @param data the contents of the authorization request
     */
    data class Query(
        val redirectUri: URI,
        val data: AuthorizationResponsePayload,
    ) : AuthorizationResponse

    /**
     * An authorization response to be communicated to verifier/RP via redirect using
     * query parameters and JARM
     * @param redirectUri the verifier/RP URI where the response will be redirected to
     * @param data the contents of the authorization request
     * @param jarmOption the verifier/RP's requirements for JARM
     */
    data class QueryJwt(
        val redirectUri: URI,
        val data: AuthorizationResponsePayload,
        val jarmOption: JarmOption,
    ) : AuthorizationResponse

    /**
     * An authorization response to be communicated to verifier/RP via redirect using
     * fragment
     * @param redirectUri the verifier/RP URI where the response will be redirected to
     * @param data the contents of the authorization request
     */
    data class Fragment(
        val redirectUri: URI,
        val data: AuthorizationResponsePayload,
    ) : AuthorizationResponse

    /**
     * An authorization response to be communicated to verifier/RP via redirect using
     * fragment and JARM
     * @param redirectUri the verifier/RP URI where the response will be redirected to
     * @param data the contents of the authorization request
     * @param jarmOption the verifier/RP's requirements for JARM
     */
    data class FragmentJwt(
        val redirectUri: URI,
        val data: AuthorizationResponsePayload,
        val jarmOption: JarmOption,
    ) : AuthorizationResponse
}

/**
 * An interface for building the [AuthorizationResponse]
 */
fun interface AuthorizationResponseBuilder {

    /**
     * Creates an [AuthorizationResponse] given a request and a consensus.
     *
     * @param requestObject the authorization request for which the response will be created
     * @param consensus the consensus of the wallet
     */
    suspend fun build(requestObject: ResolvedRequestObject, consensus: Consensus): AuthorizationResponse
}
