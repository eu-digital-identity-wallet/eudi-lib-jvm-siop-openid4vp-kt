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
import eu.europa.ec.eudi.openid4vp.internal.response.DefaultAuthorizationResponseBuilder

/**
 * An interface providing support for handling
 * an OAUTH2 authorization request that represents
 * either an SIOP authentication request, or an OpenId4VP authorization request or
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

    companion object {

        /**
         * Factory method to create a [SiopOpenId4Vp].
         *
         * @param siopOpenId4VPConfig wallet's configuration
         * @param httpClientFactory a factory to obtain a Ktor http client
         * @param signer will be used to sign the response in case the client requires a signed JARM response.
         * If provided, the signer needs to be aligned with [SiopOpenId4VPConfig.jarmConfiguration].
         *
         *
         * @return a [SiopOpenId4Vp]
         */
        operator fun invoke(
            siopOpenId4VPConfig: SiopOpenId4VPConfig,
            signer: AuthorizationResponseSigner?,
            httpClientFactory: KtorHttpClientFactory = DefaultHttpClientFactory,
        ): SiopOpenId4Vp {
            fun JarmConfiguration.Signing.requiredSigner() {
                checkNotNull(signer) { "Configuration requires signer." }
                require(supportedAlgorithms.all { alg -> alg in signer.supportedJWSAlgorithms() }) {
                    "Given signer doesn't not aligned with configuration."
                }
            }
            when (val jarmCfg = siopOpenId4VPConfig.jarmConfiguration) {
                is JarmConfiguration.Encryption -> Unit
                JarmConfiguration.NotSupported -> Unit
                is JarmConfiguration.Signing -> jarmCfg.requiredSigner()
                is JarmConfiguration.SigningAndEncryption -> jarmCfg.signing.requiredSigner()
            }

            val holderId = siopOpenId4VPConfig.holderId()
            return object :
                SiopOpenId4Vp,
                AuthorizationRequestResolver by DefaultAuthorizationRequestResolver.make(
                    httpClientFactory,
                    siopOpenId4VPConfig,
                ),
                AuthorizationResponseBuilder by DefaultAuthorizationResponseBuilder,
                Dispatcher by DefaultDispatcher(httpClientFactory, holderId, signer) {}
        }
    }
}
