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
package eu.europa.ec.eudi.openid4vp.internal.request

import com.nimbusds.jwt.SignedJWT
import com.nimbusds.openid.connect.sdk.Nonce
import eu.europa.ec.eudi.openid4vp.*
import eu.europa.ec.eudi.openid4vp.internal.ensure
import eu.europa.ec.eudi.openid4vp.internal.ensureNotNull
import io.ktor.client.*
import io.ktor.client.call.*
import io.ktor.client.request.*
import io.ktor.client.request.forms.*
import io.ktor.http.*
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import java.net.URL
import java.text.ParseException

internal class RequestFetcher(
    private val httpClient: HttpClient,
    private val siopOpenId4VPConfig: SiopOpenId4VPConfig,
) {
    /**
     * Fetches the authorization request, if needed
     */
    suspend fun fetchRequest(request: UnvalidatedRequest): FetchedRequest = when (request) {
        is UnvalidatedRequest.Plain -> FetchedRequest.Plain(request.requestObject)
        is UnvalidatedRequest.JwtSecured -> {
            val (jwt, walletNonce) = when (request) {
                is UnvalidatedRequest.JwtSecured.PassByValue -> request.jwt to null
                is UnvalidatedRequest.JwtSecured.PassByReference -> fetchJwtAndWalletNonce(request)
            }
            with(siopOpenId4VPConfig) {
                ensureValid(expectedClient = request.clientId, expectedWalletNonce = walletNonce, unverifiedJwt = jwt)
            }
        }
    }

    private suspend fun fetchJwtAndWalletNonce(
        request: UnvalidatedRequest.JwtSecured.PassByReference,
    ): Pair<Jwt, Nonce?> {
        val (_, requestUri, requestUriMethod) = request

        val supportedMethods =
            siopOpenId4VPConfig.jarConfiguration.supportedRequestUriMethods

        return when (requestUriMethod) {
            null, RequestUriMethod.GET -> {
                ensure(supportedMethods.isGetSupported()) {
                    unsupportedRequestUriMethod(RequestUriMethod.GET)
                }
                httpClient.getJAR(requestUri) to null
            }

            RequestUriMethod.POST -> {
                val postOptions =
                    ensureNotNull(supportedMethods.isPostSupported()) {
                        unsupportedRequestUriMethod(RequestUriMethod.POST)
                    }
                val walletNonce =
                    when (val nonceOption = postOptions.useWalletNonce) {
                        is NonceOption.Use -> Nonce(nonceOption.byteLength)
                        NonceOption.DoNotUse -> null
                    }
                val walletMetaData =
                    if (postOptions.includeWalletMetadata) {
                        walletMetaData(siopOpenId4VPConfig)
                    } else null
                val jwt = httpClient.postForJAR(requestUri, walletNonce, walletMetaData)
                jwt to walletNonce
            }
        }
    }
}

private fun SiopOpenId4VPConfig.ensureValid(
    expectedClient: String,
    expectedWalletNonce: Nonce?,
    unverifiedJwt: Jwt,
): FetchedRequest.JwtSecured {
    val signedJwt = ensureIsSignedJwt(unverifiedJwt).also(::ensureSupportedSigningAlgorithm)
    val clientId = ensureSameClientId(expectedClient, signedJwt)
    if (expectedWalletNonce != null) {
        ensureSameWalletNonce(expectedWalletNonce, signedJwt)
    }
    return FetchedRequest.JwtSecured(clientId, signedJwt)
}

private fun ensureIsSignedJwt(unverifiedJwt: Jwt): SignedJWT =
    try {
        SignedJWT.parse(unverifiedJwt)
    } catch (pe: ParseException) {
        throw invalidJwt("JAR JWT parse error")
    }

private fun ensureSameWalletNonce(expectedWalletNonce: Nonce, signedJwt: SignedJWT) {
    val walletNonce = signedJwt.jwtClaimsSet.getStringClaim(WALLET_NONCE_FORM_PARAM)
    ensure(expectedWalletNonce.toString() == walletNonce) {
        invalidJwt("Mismatch of wallet_nonce. Expected $expectedWalletNonce, actual $walletNonce")
    }
}

private fun SiopOpenId4VPConfig.ensureSupportedSigningAlgorithm(signedJwt: SignedJWT) {
    val signingAlg = ensureNotNull(signedJwt.header.algorithm) {
        invalidJwt("JAR is missing alg claim from header")
    }
    ensure(signingAlg in jarConfiguration.supportedAlgorithms) {
        invalidJwt("JAR is signed with ${signingAlg.name} which is not supported")
    }
}

private fun ensureSameClientId(
    expectedClientId: String,
    signedJwt: SignedJWT,
): String {
    val jarClientId = signedJwt.jwtClaimsSet.getStringClaim("client_id")
    ensure(expectedClientId == jarClientId) {
        invalidJwt("ClientId mismatch. JAR request $expectedClientId, jwt $jarClientId")
    }
    return expectedClientId
}

private fun invalidJwt(cause: String): AuthorizationRequestException =
    RequestValidationError.InvalidJarJwt(cause).asException()

private fun unsupportedRequestUriMethod(m: RequestUriMethod): AuthorizationRequestException =
    RequestValidationError.UnsupportedRequestUriMethod(m).asException()

private const val APPLICATION_JWT = "application/jwt"
private const val APPLICATION_OAUTH_AUTHZ_REQ_JWT = "application/oauth-authz-req+jwt"
private const val WALLET_NONCE_FORM_PARAM = "wallet_nonce"
private const val WALLET_METADATA_FORM_PARAM = "wallet_metadata"

private suspend fun HttpClient.getJAR(requestUri: URL): Jwt =
    get(requestUri) { addAcceptContentTypeJwt() }.body()

private suspend fun HttpClient.postForJAR(
    requestUri: URL,
    walletNonce: Nonce?,
    walletMetaData: JsonObject?,
): Jwt {
    val form =
        parameters {
            walletNonce?.let { append(WALLET_NONCE_FORM_PARAM, it.toString()) }
            walletMetaData?.let { append(WALLET_METADATA_FORM_PARAM, Json.encodeToString(it)) }
        }
    return submitForm(requestUri.toString(), form) { addAcceptContentTypeJwt() }.body<Jwt>()
}

private fun HttpRequestBuilder.addAcceptContentTypeJwt() {
    accept(ContentType.parse(APPLICATION_OAUTH_AUTHZ_REQ_JWT))
    accept(ContentType.parse(APPLICATION_JWT))
}
