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
import eu.europa.ec.eudi.prex.PresentationSubmission
import java.io.Serializable
import java.net.URI

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

/**
 * The outcome of dispatching an [Consensus] to
 * verifier/RP.
 */
sealed interface DispatchOutcome : Serializable {

    /**
     * In case verifier requested response to be redirected to a URI,
     * this class contains this URI with the response encoded to it
     */
    data class RedirectURI(val value: URI) : DispatchOutcome

    /**
     * In case verifier requested that response should be posted (direct post or direct post jwt)
     * this class contains the response of the verifier after receiving the authorization response
     */
    sealed interface VerifierResponse : DispatchOutcome {
        /**
         * When verifier/RP acknowledged the direct post
         */
        data class Accepted(val redirectURI: URI?) : VerifierResponse

        /**
         * When verifier/RP reject the direct post
         */
        data object Rejected : VerifierResponse {
            private fun readResolve(): Any = Rejected
        }
    }
}

/**
 * This interface assembles an appropriate authorization response given a [request][ResolvedRequestObject]
 * and holder's [consensus][Consensus] and then dispatches it to the verifier
 *
 *
 */
fun interface Dispatcher {

    /**
     * Assembles an appropriate authorization response given a [request][request]
     * and holder's [consensus][Consensus] and then dispatches it to the verifier.
     *
     * If [ResolvedRequestObject.responseMode] is
     * [ResponseMode.Query], [ResponseMode.QueryJwt], [ResponseMode.Fragment] or [ResponseMode.FragmentJwt]
     * dispatching takes the form of a [redirect URI][DispatchOutcome.RedirectURI] having the response
     * encoded. Wallet should redirect to this URI
     *
     * If [ResolvedRequestObject.responseMode] is [ResponseMode.DirectPost] or [ResponseMode.DirectPostJwt]
     * then dispatching takes the form of an actual post. The returned [DispatchOutcome.VerifierResponse]
     * contains the verifier's reply after receiving the post.
     *
     * @param request The request to reply to
     * @param consensus Holder's consensus (positive or negative) to this request
     * @return the dispatch outcome as described above
     */
    suspend fun dispatch(request: ResolvedRequestObject, consensus: Consensus): DispatchOutcome
}
