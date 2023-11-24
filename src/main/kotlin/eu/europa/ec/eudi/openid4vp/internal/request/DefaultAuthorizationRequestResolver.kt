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
import eu.europa.ec.eudi.openid4vp.AuthorizationRequest.JwtSecured
import eu.europa.ec.eudi.openid4vp.AuthorizationRequest.JwtSecured.PassByReference
import eu.europa.ec.eudi.openid4vp.AuthorizationRequest.JwtSecured.PassByValue
import eu.europa.ec.eudi.openid4vp.AuthorizationRequest.NotSecured
import io.ktor.client.call.*
import io.ktor.client.request.*
import io.ktor.http.*
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

internal class DefaultAuthorizationRequestResolver(
    private val ioCoroutineDispatcher: CoroutineDispatcher = Dispatchers.IO,
    private val walletOpenId4VPConfig: WalletOpenId4VPConfig,
    private val httpClientFactory: KtorHttpClientFactory = DefaultHttpClientFactory,
    private val validatedRequestObjectResolver: ValidatedRequestObjectResolver,
) : AuthorizationRequestResolver {

    override suspend fun resolveRequest(
        request: AuthorizationRequest,
    ): Resolution =
        try {
            val requestObject = requestObjectOf(request).getOrThrow()
            val validatedRequestObject = RequestObjectValidator.validate(requestObject).getOrThrow()
            val resolved = validatedRequestObjectResolver.resolve(validatedRequestObject, walletOpenId4VPConfig).getOrThrow()
            Resolution.Success(resolved)
        } catch (t: AuthorizationRequestException) {
            Resolution.Invalid(t.error)
        }

    /**
     * Extracts the [request object][RequestObject] of an [AuthorizationRequest]
     */
    private suspend fun requestObjectOf(request: AuthorizationRequest): Result<RequestObject> = runCatching {
        suspend fun fetchJwt(request: PassByReference): Jwt =
            withContext(ioCoroutineDispatcher) {
                httpClientFactory().use {
                    it.get(request.jwtURI) {
                        accept(ContentType.parse("application/oauth-authz-req+jwt"))
                    }.body<String>()
                }
            }

        when (request) {
            is NotSecured -> request.requestObject
            is JwtSecured -> {
                val jwt: Jwt = when (request) {
                    is PassByValue -> request.jwt
                    is PassByReference -> fetchJwt(request)
                }
                val clientId = request.clientId
                requestObjectFromJwt(clientId, jwt).getOrThrow()
            }
        }
    }

    /**
     * Extracts the request object from a [jwt]
     *
     * @param jwt The JWT to be validated.
     * It is assumed that represents, in its payload,
     * a [RequestObject]
     * @param clientId The client that placed request
     */
    private suspend fun requestObjectFromJwt(clientId: String, jwt: Jwt): Result<RequestObject> {
        val validator = JarJwtSignatureValidator(ioCoroutineDispatcher, walletOpenId4VPConfig)
        return validator.validate(clientId, jwt)
    }

    companion object {

        /**
         * Factory method for creating a [DefaultAuthorizationRequestResolver]
         */
        internal fun make(
            ioCoroutineDispatcher: CoroutineDispatcher = Dispatchers.IO,
            httpClientFactory: KtorHttpClientFactory,
            walletOpenId4VPConfig: WalletOpenId4VPConfig,
        ): DefaultAuthorizationRequestResolver = DefaultAuthorizationRequestResolver(
            ioCoroutineDispatcher,
            walletOpenId4VPConfig,
            httpClientFactory,
            ValidatedRequestObjectResolver(
                presentationDefinitionResolver = PresentationDefinitionResolver(
                    ioCoroutineDispatcher,
                    httpClientFactory,
                ),
                clientMetaDataResolver = ClientMetaDataResolver(
                    ioCoroutineDispatcher,
                    httpClientFactory,
                    walletOpenId4VPConfig,
                ),
            ),
        )
    }
}
