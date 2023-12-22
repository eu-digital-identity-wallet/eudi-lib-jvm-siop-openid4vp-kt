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
    private val siopOpenId4VPConfig: SiopOpenId4VPConfig,
) : AuthorizationResponseBuilder {

    override suspend fun build(
        requestObject: ResolvedRequestObject,
        consensus: Consensus,
    ): AuthorizationResponse {
        val payload = when (consensus) {
            is Consensus.NegativeConsensus -> negativeConsensusPayload(requestObject)
            is Consensus.PositiveConsensus -> positiveConsensusPayload(requestObject, consensus)
        }
        return toAuthorizationResponse(requestObject, payload)
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
        requestObject: ResolvedRequestObject,
        responseData: AuthorizationResponsePayload,
    ): AuthorizationResponse {
        fun jarmSpec() = supportedJarmSpec(requestObject.clientMetaData, siopOpenId4VPConfig)
            ?: error("Cannot create JarmSpec from passed Client Metadata")

        return when (val responseMode = requestObject.responseMode) {
            is ResponseMode.DirectPost ->
                AuthorizationResponse.DirectPost(responseMode.responseURI, responseData)

            is ResponseMode.DirectPostJwt ->
                AuthorizationResponse.DirectPostJwt(responseMode.responseURI, responseData, jarmSpec())

            is ResponseMode.Fragment ->
                AuthorizationResponse.Fragment(responseMode.redirectUri, responseData)

            is ResponseMode.FragmentJwt ->
                AuthorizationResponse.FragmentJwt(responseMode.redirectUri, responseData, jarmSpec())

            is ResponseMode.Query ->
                AuthorizationResponse.Query(responseMode.redirectUri, responseData)

            is ResponseMode.QueryJwt ->
                AuthorizationResponse.QueryJwt(responseMode.redirectUri, responseData, jarmSpec())
        }
    }
}

private fun supportedJarmSpec(
    clientMetaData: ClientMetaData,
    siopOpenId4VPConfig: SiopOpenId4VPConfig,
): JarmSpec? {
    val signed: JarmOption.SignedResponse? = clientMetaData.authorizationSignedResponseAlg?.let { jwsAlgorithm ->
        siopOpenId4VPConfig.supportedResponseSigner(jwsAlgorithm)?.let { signer ->
            JarmOption.SignedResponse(jwsAlgorithm, signer)
        }
    }

    val encrypted: JarmOption.EncryptedResponse? =
        clientMetaData.authorizationEncryptedResponseAlg?.let { jweAlg ->
            clientMetaData.authorizationEncryptedResponseEnc?.let { encMethod ->
                clientMetaData.jwkSet?.let { jwkSet ->
                    JarmOption.EncryptedResponse(jweAlg, encMethod, jwkSet)
                }
            }
        }
    val jarmOption = when {
        signed != null && encrypted != null -> JarmOption.SignedAndEncryptedResponse(signed, encrypted)
        signed != null && encrypted == null -> signed
        signed == null && encrypted != null -> encrypted
        else -> null
    }

    val holderId = when (val jarmCfg = siopOpenId4VPConfig.jarmConfiguration) {
        is JarmConfiguration.Signing -> jarmCfg.holderId
        is JarmConfiguration.Encryption -> jarmCfg.holderId
        is JarmConfiguration.SigningAndEncryption -> jarmCfg.signing.holderId
        JarmConfiguration.NotSupported -> null
    }
    return if (holderId != null && jarmOption != null) JarmSpec(holderId, jarmOption)
    else null
}
