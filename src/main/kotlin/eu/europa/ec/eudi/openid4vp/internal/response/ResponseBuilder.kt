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
package eu.europa.ec.eudi.openid4vp.internal.response

import eu.europa.ec.eudi.openid4vp.*
import eu.europa.ec.eudi.openid4vp.AuthorizationResponsePayload.*
import eu.europa.ec.eudi.openid4vp.Consensus.PositiveConsensus.*

internal fun authorizationResponse(
    requestObject: ResolvedRequestObject,
    consensus: Consensus,
): AuthorizationResponse {
    val payload = requestObject.responsePayload(consensus)
    return requestObject.responseWith(payload)
}

private fun ResolvedRequestObject.responsePayload(
    consensus: Consensus,
): AuthorizationResponsePayload = when (consensus) {
    is Consensus.NegativeConsensus -> NoConsensusResponseData(state, clientId)
    is Consensus.PositiveConsensus -> when (this) {
        is ResolvedRequestObject.SiopAuthentication -> {
            require(consensus is IdTokenConsensus) { "IdTokenConsensus expected" }
            SiopAuthentication(
                consensus.idToken,
                state,
                clientId,
            )
        }

        is ResolvedRequestObject.OpenId4VPAuthorization -> {
            require(consensus is VPTokenConsensus) { "VPTokenConsensus expected" }
            OpenId4VPAuthorization(
                consensus.vpToken,
                consensus.presentationSubmission,
                state,
                clientId,
            )
        }

        is ResolvedRequestObject.SiopOpenId4VPAuthentication -> {
            require(consensus is IdAndVPTokenConsensus) { "IdAndVPTokenConsensus expected" }
            SiopOpenId4VPAuthentication(
                consensus.idToken,
                consensus.vpToken,
                consensus.presentationSubmission,
                state,
                clientId,
            )
        }
    }
}

private fun ResolvedRequestObject.responseWith(
    data: AuthorizationResponsePayload,
): AuthorizationResponse {
    fun jarmOption() = checkNotNull(jarmOption)

    return when (val responseMode = responseMode) {
        is ResponseMode.DirectPost ->
            AuthorizationResponse.DirectPost(responseMode.responseURI, data)

        is ResponseMode.DirectPostJwt ->
            AuthorizationResponse.DirectPostJwt(responseMode.responseURI, data, jarmOption())

        is ResponseMode.Fragment ->
            AuthorizationResponse.Fragment(responseMode.redirectUri, data)

        is ResponseMode.FragmentJwt ->
            AuthorizationResponse.FragmentJwt(responseMode.redirectUri, data, jarmOption())

        is ResponseMode.Query ->
            AuthorizationResponse.Query(responseMode.redirectUri, data)

        is ResponseMode.QueryJwt ->
            AuthorizationResponse.QueryJwt(responseMode.redirectUri, data, jarmOption())
    }
}
