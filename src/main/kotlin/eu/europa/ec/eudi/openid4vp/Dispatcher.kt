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
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.Dispatchers
import java.io.Serializable
import java.net.URI

/**
 * The outcome of dispatching an [AuthorizationResponse] to
 * verifier/RP.
 */
sealed interface DispatchOutcome : Serializable {

    /**
     * The outcome of dispatching a [AuthorizationResponse.RedirectResponse]
     * Actually, in this case there are no side effects, just
     * the [redirect URI][value]
     */
    data class RedirectURI(val value: URI) : DispatchOutcome

    /**
     * The verifier/RP's response to a [direct post][AuthorizationResponse.RedirectResponse]
     */
    sealed interface VerifierResponse : DispatchOutcome {
        /**
         * When verifier/RP acknowledged the direct post
         */
        data class Accepted(val redirectURI: URI?) : VerifierResponse

        /**
         * When verifier/RP reject the direct post
         */
        data object Rejected : VerifierResponse {
            private fun readResolve(): Any = Rejected
        }
    }
}

/**
 * Depending on the kind of [AuthorizationResponse], the interface
 * either dispatches the authorization response to the verifier/ RP
 * in the case of [director post][AuthorizationResponse.DirectPostResponse],
 * or produces an appropriate [redirect_uri][DispatchOutcome.RedirectURI],
 * in the case of [redirect][AuthorizationResponse.RedirectResponse]
 */
fun interface Dispatcher {

    /**
     * Method dispatches the given [response] to the verifier / RP.
     * In case of a [director post][AuthorizationResponse.DirectPostResponse] method performs the HTTP Post to
     * the verifier end-point (response_uri).
     * In case of a [redirect][AuthorizationResponse.RedirectResponse] method prepares an appropriate redirect_uri
     *
     * @param response the response to be dispatched to the verifier / RP
     * @return in case of [director post][AuthorizationResponse.DirectPostResponse] method returns
     * the [verifier's response][DispatchOutcome.VerifierResponse].
     * In the case of a [redirect][AuthorizationResponse.RedirectResponse]
     * method returns an appropriate [redirect_uri][DispatchOutcome.RedirectURI]
     */
    suspend fun dispatch(response: AuthorizationResponse): DispatchOutcome

    companion object {

        /**
         * Factory method to create a [Dispatcher].
         *
         * @param ioCoroutineDispatcher the coroutine dispatcher to handle IO
         * @param httpClientFactory a factory to obtain a Ktor http client
         * @return a [Dispatcher]
         *
         * @see DefaultDispatcher
         */
        fun make(
            ioCoroutineDispatcher: CoroutineDispatcher = Dispatchers.IO,
            httpClientFactory: KtorHttpClientFactory = DefaultHttpClientFactory,
        ): Dispatcher =
            DefaultDispatcher(ioCoroutineDispatcher, httpClientFactory)
    }
}
