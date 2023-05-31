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

import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.Dispatchers

/**
 * An interface providing support for handling
 * an OAUTH2 authorization request that represents
 * either an SIOP authentication request, or a OpenId4VP authorization request or
 * a combined SIOP & OpenId4VP request
 *
 * The support is grouped into three groups:
 * [validate & resolve][AuthorizationRequestResolver]
 * [build response][AuthorizationResponseBuilder]
 * [dispatch response][Dispatcher]
 *
 * @see AuthorizationRequestResolver
 * @see AuthorizationResponseBuilder
 * @see Dispatcher
 */
interface SiopOpenId4Vp : AuthorizationRequestResolver, AuthorizationResponseBuilder, Dispatcher {

    /**
     *
     */
    suspend fun handle(
        uri: String,
        holderConsensus: suspend (ResolvedRequestObject) -> Consensus,
    ): DispatchOutcome =
        when (val resolution = resolveRequestUri(uri)) {
            is Resolution.Invalid -> throw resolution.error.asException()
            is Resolution.Success -> {
                val requestObject = resolution.requestObject
                val consensus = holderConsensus(requestObject)
                val authorizationResponse = build(requestObject, consensus)
                dispatch(authorizationResponse)
            }
        }

    companion object {

        /**
         * Factory method to create a [SiopOpenId4Vp] based
         * on ktor
         *
         * @param ioCoroutineDispatcher the coroutine dispatcher to handle IO
         * @param walletOpenId4VPConfig wallet's configuration
         * @param httpClientFactory a factory to obtain Ktor http client
         * @return a [SiopOpenId4Vp]
         *
         * @see SiopOpenId4VpKtor
         */
        fun ktor(
            walletOpenId4VPConfig: WalletOpenId4VPConfig,
            ioCoroutineDispatcher: CoroutineDispatcher = Dispatchers.IO,
            httpClientFactory: KtorHttpClientFactory = SiopOpenId4VpKtor.DefaultFactory,
        ): SiopOpenId4Vp = SiopOpenId4VpKtor(ioCoroutineDispatcher, walletOpenId4VPConfig, httpClientFactory)
    }
}
