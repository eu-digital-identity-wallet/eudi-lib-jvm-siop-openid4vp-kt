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

import eu.europa.ec.eudi.openid4vp.SiopOpenId4Vp.Companion.invoke
import eu.europa.ec.eudi.openid4vp.internal.request.DefaultRequestResolverOverHttp
import eu.europa.ec.eudi.openid4vp.internal.response.DefaultDispatcherOverHttp
import io.ktor.client.*

/**
 * An interface providing support for handling an OAUTH2 request that represents
 * either an SIOP authentication request,
 * or an OpenId4VP authorization request
 * or a combined SIOP & OpenId4VP request.
 *
 * To obtain an instance of [SiopOpenId4Vp], method [invoke] can be used.
 *
 * @see AuthorizationRequestOverHttpResolver
 * @see DispatcherOverHttp
 */
interface SiopOpenId4Vp : AuthorizationRequestOverHttpResolver, DispatcherOverHttp, ErrorDispatcher {

    companion object {

        /**
         * Factory method to create a [SiopOpenId4Vp].
         *
         * @param siopOpenId4VPConfig wallet's configuration
         * @param httpClient A Ktor http client. This can be used to configure ktor
         * to use a specific engine.
         *
         * @return a [SiopOpenId4Vp]
         */
        operator fun invoke(
            siopOpenId4VPConfig: SiopOpenId4VPConfig,
            httpClient: HttpClient,
        ): SiopOpenId4Vp {
            val requestResolver = DefaultRequestResolverOverHttp(siopOpenId4VPConfig, httpClient)
            val dispatcher = DefaultDispatcherOverHttp(httpClient)
            return object :
                AuthorizationRequestOverHttpResolver by requestResolver,
                DispatcherOverHttp by dispatcher,
                ErrorDispatcher by dispatcher,
                SiopOpenId4Vp {}
        }
    }
}
