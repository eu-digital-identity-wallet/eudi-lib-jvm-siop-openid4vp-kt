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

import eu.europa.ec.eudi.openid4vp.Jwt
import eu.europa.ec.eudi.openid4vp.KtorHttpClientFactory
import io.ktor.client.call.*
import io.ktor.client.request.*
import io.ktor.http.*

internal class RequestFetcher(private val httpClientFactory: KtorHttpClientFactory) {

    suspend fun fetch(request: UnvalidatedRequest): FetchedRequest = when (request) {
        is UnvalidatedRequest.Plain -> FetchedRequest.Plain(request.requestObject)
        is UnvalidatedRequest.JwtSecured.PassByValue -> FetchedRequest.JwtSecured(request.clientId, request.jwt)
        is UnvalidatedRequest.JwtSecured.PassByReference -> FetchedRequest.JwtSecured(request.clientId, request.jwt())
    }

    private suspend fun UnvalidatedRequest.JwtSecured.PassByReference.jwt(): Jwt {
        return httpClientFactory().use { client ->
            client.get(jwtURI) {
                accept(ContentType.parse("application/oauth-authz-req+jwt"))
            }.body<String>()
        }
    }
}
