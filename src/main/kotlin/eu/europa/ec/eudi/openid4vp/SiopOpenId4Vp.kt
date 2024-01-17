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

import eu.europa.ec.eudi.openid4vp.internal.response.DefaultDispatcher

/**
 * An interface providing support for handling an OAUTH2 request that represents
 * either an SIOP authentication request,
 * or an OpenId4VP authorization request
 * or a combined SIOP & OpenId4VP request.
 *
 * To obtain an instance of [SiopOpenId4Vp], method [invoke] can be used.
 *
 * @see AuthorizationRequestResolver
 * @see Dispatcher
 */
interface SiopOpenId4Vp : AuthorizationRequestResolver, Dispatcher {

    companion object {

        /**
         * Factory method to create a [SiopOpenId4Vp].
         *
         * @param siopOpenId4VPConfig wallet's configuration
         * @param httpClientFactory a factory to obtain a Ktor http client. This can be used to configure ktor
         * to use a specific engine. If a factory is not provided, the [DefaultHttpClientFactory] will be used,
         * which peeks the actual engine from whatever is available in the classpath.
         *
         * @return a [SiopOpenId4Vp]
         */
        operator fun invoke(
            siopOpenId4VPConfig: SiopOpenId4VPConfig,
            httpClientFactory: KtorHttpClientFactory = DefaultHttpClientFactory,
        ): SiopOpenId4Vp {
            val requestResolver = AuthorizationRequestResolver(siopOpenId4VPConfig, httpClientFactory)
            val dispatcher = DefaultDispatcher(siopOpenId4VPConfig, httpClientFactory)
            return object :
                AuthorizationRequestResolver by requestResolver,
                Dispatcher by dispatcher,
                SiopOpenId4Vp {}
        }
    }
}
