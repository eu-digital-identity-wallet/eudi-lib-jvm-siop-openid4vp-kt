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
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put

/**
 * Default implementation of [DispatcherOverDCApi]
 */
internal class DefaultDispatcherOverDCApi(private val siopOpenId4VPConfig: SiopOpenId4VPConfig) : DispatcherOverDCApi {

    override suspend fun assembleResponse(
        request: ResolvedRequestObject,
        consensus: Consensus,
        encryptionParameters: EncryptionParameters?,
    ): JsonObject {
        val response = request.responseWith(consensus, encryptionParameters)
        require(response is AuthorizationResponse.DCApi || response is AuthorizationResponse.DCApiJwt) {
            "Unsupported response type: ${response::class.simpleName} for request type: ${request::class.simpleName}"
        }
        return doAssemble(response)
    }

    internal fun doAssemble(response: AuthorizationResponse): JsonObject = buildJsonObject {
        when (response) {
            is AuthorizationResponse.DCApi -> {
                response.data.asMap().entries.forEach { (key, value) -> put(key, value) }
            }
            is AuthorizationResponse.DCApiJwt -> {
                val encryptedJwt = response.responseEncryptionSpecification?.encrypt(response.data)
                put("response", JsonPrimitive(encryptedJwt))
            }
            else -> error("Unsupported authorization response ${response::class::simpleName} for dispatching over DC API")
        }
    }
}
