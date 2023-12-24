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
