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

import eu.europa.ec.eudi.openid4vp.internal.dispatch.DefaultDispatcher
import eu.europa.ec.eudi.openid4vp.internal.request.DefaultAuthorizationRequestResolver
import io.ktor.client.*
import io.ktor.client.plugins.contentnegotiation.*
import io.ktor.serialization.kotlinx.json.*
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.Dispatchers

/**
 * Alias of a method that creates a [HttpClient]
 */
typealias KtorHttpClientFactory = () -> HttpClient

/**
 * An implementation of [SiopOpenId4Vp] that uses Ktor
 *
 */
class SiopOpenId4VpKtor(
    private val ioCoroutineDispatcher: CoroutineDispatcher = Dispatchers.IO,
    private val walletOpenId4VPConfig: WalletOpenId4VPConfig,
    private val httpClientFactory: KtorHttpClientFactory = DefaultFactory,
) : SiopOpenId4Vp {

    override suspend fun resolveRequest(request: AuthorizationRequest): Resolution =
        authorizationResolver(ioCoroutineDispatcher, walletOpenId4VPConfig, httpClientFactory).resolveRequest(request)

    override suspend fun build(requestObject: ResolvedRequestObject, consensus: Consensus): AuthorizationResponse =
        AuthorizationResponseBuilder.make(walletOpenId4VPConfig).build(requestObject, consensus)

    override suspend fun dispatch(response: AuthorizationResponse): DispatchOutcome =
        dispatcher(ioCoroutineDispatcher, httpClientFactory).dispatch(response)

    companion object {

        /**
         * Factory which produces a [Ktor Http client][HttpClient]
         * The actual engine will be peeked up by whatever
         * it is available in classpath
         *
         * @see [Ktor Client]("https://ktor.io/docs/client-dependencies.html#engine-dependency)
         */
        val DefaultFactory: KtorHttpClientFactory = {
            HttpClient {
                install(ContentNegotiation) { json() }
                expectSuccess = true
            }
        }

        /**
         * Factory method for creating an [AuthorizationRequestResolver] that
         * uses the provided [KtorHttpClientFactory] to obtain a [HttpClient]
         * which in turn is used, if needed, to contact the verifier's end-points
         *
         * The [AuthorizationRequestResolver] will obtain a new [HttpClient] with each call & then release it
         *
         * @param walletOpenId4VPConfig wallet configuration
         * @param httpClientFactory factory to obtain [HttpClient]
         * @return an [AuthorizationRequestResolver] as described above
         *
         * @see DefaultAuthorizationRequestResolver
         */
        fun authorizationResolver(
            ioCoroutineDispatcher: CoroutineDispatcher = Dispatchers.IO,
            walletOpenId4VPConfig: WalletOpenId4VPConfig,
            httpClientFactory: KtorHttpClientFactory = DefaultFactory,
        ): AuthorizationRequestResolver =
            DefaultAuthorizationRequestResolver.make(
                ioCoroutineDispatcher,
                httpClientFactory,
                walletOpenId4VPConfig,
            )

        /**
         * Factory method for creating an [Dispatcher] that
         * uses the provided [KtorHttpClientFactory] to obtain a [HttpClient]
         * which in turn is used, if needed, to contact the verifier's end-points.
         *
         * The [Dispatcher] will obtain a new [HttpClient] with each call & then release it
         *
         * @param httpClientFactory factory to obtain [HttpClient]
         * @param ioCoroutineDispatcher the co-routines dispatcher to handle IO
         * @return the [Dispatcher] as described above
         * @see DefaultDispatcher
         */
        fun dispatcher(
            ioCoroutineDispatcher: CoroutineDispatcher = Dispatchers.IO,
            httpClientFactory: KtorHttpClientFactory = DefaultFactory,
        ): Dispatcher = DefaultDispatcher(ioCoroutineDispatcher, httpClientFactory)
    }
}
