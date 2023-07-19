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

/**
 * Default implementation of [AuthorizationResponseBuilder]
 */
internal class DefaultAuthorizationResponseBuilder(
    private val walletOpenId4VPConfig: WalletOpenId4VPConfig,
) : AuthorizationResponseBuilder {

    override suspend fun build(
        requestObject: ResolvedRequestObject,
        consensus: Consensus,
    ): AuthorizationResponse {
        val payload = when (consensus) {
            is Consensus.NegativeConsensus -> negativeConsensusPayload(requestObject)
            is Consensus.PositiveConsensus -> positiveConsensusPayload(requestObject, consensus)
        }
        val jarmSpec = JarmSpec.make(requestObject.clientMetaData, walletOpenId4VPConfig)
        return toAuthorizationResponse(requestObject.responseMode, payload, jarmSpec)
    }

    private fun positiveConsensusPayload(
        requestObject: ResolvedRequestObject,
        consensus: Consensus.PositiveConsensus,
    ): AuthorizationResponsePayload = when (requestObject) {
        is ResolvedRequestObject.SiopAuthentication -> when (consensus) {
            is IdTokenConsensus -> SiopAuthentication(
                consensus.idToken,
                requestObject.state,
                requestObject.clientId,
            )
            else -> null
        }

        is ResolvedRequestObject.OpenId4VPAuthorization -> when (consensus) {
            is VPTokenConsensus -> OpenId4VPAuthorization(
                consensus.vpToken,
                consensus.presentationSubmission,
                requestObject.state,
                requestObject.clientId,
            )
            else -> null
        }

        is ResolvedRequestObject.SiopOpenId4VPAuthentication -> when (consensus) {
            is IdAndVPTokenConsensus -> SiopOpenId4VPAuthentication(
                consensus.idToken,
                consensus.vpToken,
                consensus.presentationSubmission,
                requestObject.state,
                requestObject.clientId,
            )
            else -> null
        }
    } ?: error("Unexpected consensus")

    private fun negativeConsensusPayload(requestObject: ResolvedRequestObject): NoConsensusResponseData =
        NoConsensusResponseData(requestObject.state, requestObject.clientId)

    private fun toAuthorizationResponse(
        responseMode: ResponseMode,
        responseData: AuthorizationResponsePayload,
        jarmSpec: JarmSpec,
    ): AuthorizationResponse = when (responseMode) {
        is ResponseMode.DirectPost -> AuthorizationResponse.DirectPost(responseMode.responseURI, responseData)
        is ResponseMode.DirectPostJwt -> AuthorizationResponse.DirectPostJwt(responseMode.responseURI, responseData, jarmSpec)
        is ResponseMode.Fragment -> AuthorizationResponse.Fragment(responseMode.redirectUri, responseData)
        is ResponseMode.FragmentJwt -> AuthorizationResponse.FragmentJwt(responseMode.redirectUri, responseData, jarmSpec)
        is ResponseMode.Query -> AuthorizationResponse.Query(responseMode.redirectUri, responseData)
        is ResponseMode.QueryJwt -> AuthorizationResponse.QueryJwt(responseMode.redirectUri, responseData, jarmSpec)
    }
}
