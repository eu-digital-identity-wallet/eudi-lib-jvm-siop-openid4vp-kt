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
import java.io.Serializable
import java.net.URI
import java.net.URL

/**
 * The payload of an [AuthorizationResponse]
 */
internal sealed interface AuthorizationResponsePayload : Serializable {

    val nonce: String
    val state: String?
    val clientId: VerifierId
    val encryptionParameters: EncryptionParameters?

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
        override val nonce: String,
        override val state: String?,
        override val clientId: VerifierId,
        override val encryptionParameters: EncryptionParameters? = null,
    ) : Success

    /**
     * In response to a [ResolvedRequestObject.OpenId4VPAuthorization]
     * and holder's [Consensus.PositiveConsensus.VPTokenConsensus]
     *
     * @param vpContent the vp related information
     * that fulfils the [ResolvedRequestObject.OpenId4VPAuthorization.presentationQuery]
     * @param state the state of the [ request][ResolvedRequestObject.OpenId4VPAuthorization.state]
     * @param encryptionParameters the encryption parameters that may be needed during the response dispatch
     */
    data class OpenId4VPAuthorization(
        val vpContent: VpContent,
        override val nonce: String,
        override val state: String?,
        override val clientId: VerifierId,
        override val encryptionParameters: EncryptionParameters? = null,
    ) : Success

    /**
     * In response to a [ResolvedRequestObject.SiopOpenId4VPAuthentication]
     * and holder's [Consensus.PositiveConsensus.IdAndVPTokenConsensus]
     *
     * @param idToken The id_token produced by the wallet
     * @param vpContent the vp related information
     * that fulfils the [ResolvedRequestObject.OpenId4VPAuthorization.presentationQuery]
     * @param state the state of the [request][ResolvedRequestObject.SiopOpenId4VPAuthentication.state]
     * @param encryptionParameters the encryption parameters that may be needed during the response dispatch
     */
    data class SiopOpenId4VPAuthentication(
        val idToken: Jwt,
        val vpContent: VpContent,
        override val nonce: String,
        override val state: String?,
        override val clientId: VerifierId,
        override val encryptionParameters: EncryptionParameters? = null,
    ) : Success

    sealed interface Failed : AuthorizationResponsePayload

    /**
     * In response of an [Resolution.Invalid] authorization request
     * @param error the cause
     * @param state the state of the request
     */
    data class InvalidRequest(
        val error: AuthorizationRequestError,
        override val nonce: String,
        override val state: String?,
        override val clientId: VerifierId,
        override val encryptionParameters: EncryptionParameters? = null,
    ) : Failed

    /**
     * In response of a [ResolvedRequestObject] and
     * holder's [negative consensus][Consensus.NegativeConsensus]
     * @param state the state of the [request][ResolvedRequestObject.state]
     */
    data class NoConsensusResponseData(
        override val nonce: String,
        override val state: String?,
        override val clientId: VerifierId,
        override val encryptionParameters: EncryptionParameters? = null,
    ) : Failed
}

/**
 * An OAUTH2 authorization response
 */
internal sealed interface AuthorizationResponse : Serializable {

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
     * @param jarmRequirement the verifier/RP's requirements for JARM
     */
    data class DirectPostJwt(
        val responseUri: URL,
        val data: AuthorizationResponsePayload,
        val jarmRequirement: JarmRequirement,
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
     * @param jarmRequirement the verifier/RP's requirements for JARM
     */
    data class QueryJwt(
        val redirectUri: URI,
        val data: AuthorizationResponsePayload,
        val jarmRequirement: JarmRequirement,
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
     * @param jarmRequirement the verifier/RP's requirements for JARM
     */
    data class FragmentJwt(
        val redirectUri: URI,
        val data: AuthorizationResponsePayload,
        val jarmRequirement: JarmRequirement,
    ) : AuthorizationResponse
}

internal fun ResolvedRequestObject.responseWith(
    consensus: Consensus,
    encryptionParameters: EncryptionParameters?,
): AuthorizationResponse {
    val payload = responsePayload(consensus, encryptionParameters)
    return responseWith(payload)
}

private fun ResolvedRequestObject.responsePayload(
    consensus: Consensus,
    encryptionParameters: EncryptionParameters?,
): AuthorizationResponsePayload = when (consensus) {
    is Consensus.NegativeConsensus -> AuthorizationResponsePayload.NoConsensusResponseData(nonce, state, client.id)
    is Consensus.PositiveConsensus -> when (this) {
        is ResolvedRequestObject.SiopAuthentication -> {
            require(consensus is Consensus.PositiveConsensus.IdTokenConsensus) { "IdTokenConsensus expected" }
            AuthorizationResponsePayload.SiopAuthentication(
                consensus.idToken,
                nonce,
                state,
                client.id,
                encryptionParameters,
            )
        }

        is ResolvedRequestObject.OpenId4VPAuthorization -> {
            require(consensus is Consensus.PositiveConsensus.VPTokenConsensus) { "VPTokenConsensus expected" }
            AuthorizationResponsePayload.OpenId4VPAuthorization(
                consensus.vpContent,
                nonce,
                state,
                client.id,
                encryptionParameters,
            )
        }

        is ResolvedRequestObject.SiopOpenId4VPAuthentication -> {
            require(consensus is Consensus.PositiveConsensus.IdAndVPTokenConsensus) { "IdAndVPTokenConsensus expected" }
            AuthorizationResponsePayload.SiopOpenId4VPAuthentication(
                consensus.idToken,
                consensus.vpContent,
                nonce,
                state,
                client.id,
                encryptionParameters,
            )
        }
    }
}

private fun ResolvedRequestObject.responseWith(
    data: AuthorizationResponsePayload,
): AuthorizationResponse {
    fun jarmOption() = checkNotNull(jarmRequirement)

    return when (val mode = responseMode) {
        is ResponseMode.DirectPost -> AuthorizationResponse.DirectPost(mode.responseURI, data)
        is ResponseMode.DirectPostJwt -> AuthorizationResponse.DirectPostJwt(mode.responseURI, data, jarmOption())
        is ResponseMode.Fragment -> AuthorizationResponse.Fragment(mode.redirectUri, data)
        is ResponseMode.FragmentJwt -> AuthorizationResponse.FragmentJwt(mode.redirectUri, data, jarmOption())
        is ResponseMode.Query -> AuthorizationResponse.Query(mode.redirectUri, data)
        is ResponseMode.QueryJwt -> AuthorizationResponse.QueryJwt(mode.redirectUri, data, jarmOption())
    }
}
