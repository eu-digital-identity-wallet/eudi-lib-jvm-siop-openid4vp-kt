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

/**
 * Default implementation of [AuthorizationResponseBuilder]
 */
internal object DefaultAuthorizationResponseBuilder : AuthorizationResponseBuilder {

    override suspend fun build(
        requestObject: ResolvedRequestObject,
        consensus: Consensus,
    ): AuthorizationResponse =

        if (consensus is Consensus.NegativeConsensus) {
            buildNoConsensusResponse(requestObject)
        } else {
            fun unexpected(): AuthorizationResponse = error("Unexpected consensus")
            when (requestObject) {
                is ResolvedRequestObject.SiopAuthentication -> when (consensus) {
                    is Consensus.PositiveConsensus.IdTokenConsensus -> buildResponse(requestObject, consensus)
                    else -> unexpected()
                }

                is ResolvedRequestObject.OpenId4VPAuthorization -> when (consensus) {
                    is Consensus.PositiveConsensus.VPTokenConsensus -> buildResponse(requestObject, consensus)
                    else -> unexpected()
                }

                is ResolvedRequestObject.SiopOpenId4VPAuthentication -> when (consensus) {
                    is Consensus.PositiveConsensus.IdAndVPTokenConsensus -> buildResponse(requestObject, consensus)
                    else -> unexpected()
                }
            }
        }

    private suspend fun buildResponse(
        requestObject: ResolvedRequestObject.SiopAuthentication,
        consensus: Consensus.PositiveConsensus.IdTokenConsensus,
    ): AuthorizationResponse {
        val payload = AuthorizationResponsePayload.SiopAuthenticationResponse(consensus.idToken, requestObject.state)
        return toAuthorizationResponse(requestObject.responseMode, payload)
    }

    private suspend fun buildResponse(
        requestObject: ResolvedRequestObject.OpenId4VPAuthorization,
        consensus: Consensus.PositiveConsensus.VPTokenConsensus,
    ): AuthorizationResponse {
        error("Not yet implemented")
    }

    private suspend fun buildResponse(
        requestObject: ResolvedRequestObject.SiopOpenId4VPAuthentication,
        consensus: Consensus.PositiveConsensus.IdAndVPTokenConsensus,
    ): AuthorizationResponse {
        error("Not yet implemented")
    }

    private suspend fun buildNoConsensusResponse(requestObject: ResolvedRequestObject): AuthorizationResponse {
        val payload = AuthorizationResponsePayload.NoConsensusResponseData(requestObject.state)
        return toAuthorizationResponse(requestObject.responseMode, payload)
    }

    private fun toAuthorizationResponse(
        responseMode: ResponseMode,
        responseData: AuthorizationResponsePayload,
    ): AuthorizationResponse = when (responseMode) {
        is ResponseMode.DirectPost -> AuthorizationResponse.DirectPost(responseMode.responseURI, responseData)
        is ResponseMode.DirectPostJwt -> AuthorizationResponse.DirectPostJwt(responseMode.responseURI, responseData)
        is ResponseMode.Fragment -> AuthorizationResponse.Fragment(responseMode.redirectUri, responseData)
        is ResponseMode.FragmentJwt -> AuthorizationResponse.FragmentJwt(responseMode.redirectUri, responseData)
        is ResponseMode.Query -> AuthorizationResponse.Query(responseMode.redirectUri, responseData)
        is ResponseMode.QueryJwt -> AuthorizationResponse.QueryJwt(responseMode.redirectUri, responseData)
    }
}
