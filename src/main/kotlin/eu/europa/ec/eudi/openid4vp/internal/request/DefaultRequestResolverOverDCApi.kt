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

import eu.europa.ec.eudi.openid4vp.*
import eu.europa.ec.eudi.openid4vp.internal.JwsJson
import eu.europa.ec.eudi.openid4vp.internal.jsonSupport
import eu.europa.ec.eudi.openid4vp.internal.request.ReceivedRequest.Signed
import eu.europa.ec.eudi.openid4vp.internal.request.ReceivedRequest.Unsigned
import io.ktor.client.*
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.decodeFromJsonElement
import kotlinx.serialization.json.jsonPrimitive

internal class DefaultRequestResolverOverDCApi(
    private val siopOpenId4VPConfig: SiopOpenId4VPConfig,
    private val httpClient: HttpClient,
) : AuthorizationRequestOverDCApiResolver {

    override suspend fun resolveRequestObject(origin: String, requestData: JsonObject): Resolution =
        with(httpClient) {
            this.resolveRequestObject(origin, requestData)
        }

    private suspend fun HttpClient.resolveRequestObject(origin: String, requestData: JsonObject): Resolution {
        val receivedRequest = ReceivedRequest.make(requestData).getOrThrow()

        val authenticatedRequest =
            try {
                authenticateRequest(origin, receivedRequest)
            } catch (e: AuthorizationRequestException) {
                return Resolution.Invalid(e.error, null)
            }

        val resolved =
            try {
                validateRequestObject(authenticatedRequest)
            } catch (e: AuthorizationRequestException) {
                return Resolution.Invalid(e.error, null)
            }

        return Resolution.Success(resolved)
    }

    private suspend fun HttpClient.authenticateRequest(origin: String, receivedRequest: ReceivedRequest): AuthenticatedRequest {
        val requestAuthenticator = RequestAuthenticator(siopOpenId4VPConfig, this)
        return requestAuthenticator.authenticateRequestOverDCApi(origin, receivedRequest)
    }

    private fun validateRequestObject(authenticatedRequest: AuthenticatedRequest): ResolvedRequestObject {
        val requestValidator = RequestObjectValidator(siopOpenId4VPConfig)
        return requestValidator.validateDCApiRequestObject(authenticatedRequest)
    }

    fun ReceivedRequest.Companion.make(requestData: JsonObject): Result<ReceivedRequest> = runCatching {
        val requestValue = requestData["request"]

        when {
            requestValue != null && requestValue is JsonObject -> {
                val jwsJson = jsonSupport.decodeFromJsonElement<JwsJson>(requestValue)
                Signed(jwsJson)
            }

            requestValue != null && requestValue is JsonPrimitive -> {
                val jwsJson = JwsJson.from(requestValue.jsonPrimitive.content).getOrThrow()
                Signed(jwsJson)
            }

            else -> Unsigned(jsonSupport.decodeFromJsonElement(requestData))
        }
    }
}
