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

import com.eygraber.uri.Uri
import com.nimbusds.jwt.SignedJWT
import eu.europa.ec.eudi.openid4vp.*
import eu.europa.ec.eudi.openid4vp.internal.ensure
import eu.europa.ec.eudi.openid4vp.internal.request.UnvalidatedRequest.JwtSecured.PassByReference
import eu.europa.ec.eudi.openid4vp.internal.request.UnvalidatedRequest.JwtSecured.PassByValue
import io.ktor.client.*
import io.ktor.client.plugins.*
import kotlinx.serialization.Required
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.jsonObject
import java.net.URL

/**
 * The data of an OpenID4VP authorization request or SIOP Authentication request
 * or a combined OpenId4VP & SIOP request
 * without any validation and regardless of the way they sent to the wallet
 */
@Serializable
internal data class UnvalidatedRequestObject(
    @SerialName("client_metadata") val clientMetaData: JsonObject? = null,
    @Required val nonce: String? = null,
    @SerialName("client_id") val clientId: String? = null,
    @SerialName("response_type") val responseType: String? = null,
    @SerialName("response_mode") val responseMode: String? = null,
    @SerialName("response_uri") val responseUri: String? = null,
    @SerialName("presentation_definition") val presentationDefinition: JsonObject? = null,
    @SerialName("presentation_definition_uri") val presentationDefinitionUri: String? = null, // Not utilized from ISO-23330-4
    @SerialName("dcql_query") val dcqlQuery: JsonObject? = null,
    @SerialName("redirect_uri") val redirectUri: String? = null,
    val scope: String? = null,
    @SerialName("supported_algorithm") val supportedAlgorithm: String? = null,
    val state: String? = null, // OpenId4VP specific, not utilized from ISO-23330-4
    @SerialName("id_token_type") val idTokenType: String? = null,
)

enum class RequestUriMethod {
    GET, POST
}

/**
 * OAUTH2 authorization request
 *
 * This is merely a data carrier structure that doesn't enforce any rules.
 */
internal sealed interface UnvalidatedRequest {

    data class Plain(val requestObject: UnvalidatedRequestObject) : UnvalidatedRequest

    /**
     * JWT Secured authorization request (JAR)
     */
    sealed interface JwtSecured : UnvalidatedRequest {
        /**
         * The <em>client_id</em> of the verifier
         */
        val clientId: String

        /**
         * A JAR passed by value
         */
        data class PassByValue(override val clientId: String, val jwt: Jwt) : JwtSecured

        /**
         * A JAR passed by reference
         */
        data class PassByReference(
            override val clientId: String,
            val jwtURI: URL,
            val requestURIMethod: RequestUriMethod?,
        ) : JwtSecured
    }

    companion object {

        /**
         * Convenient method for parsing a URI representing an OAUTH2 Authorization request.
         */
        fun make(uriStr: String): Result<UnvalidatedRequest> = runCatching {
            val uri = Uri.parse(uriStr)
            fun clientId(): String =
                uri.getQueryParameter("client_id")
                    ?: throw RequestValidationError.MissingClientId.asException()

            val requestValue = uri.getQueryParameter("request")
            val requestUriValue = uri.getQueryParameter("request_uri")
            val requestUriMethod =
                uri.getQueryParameter("request_uri_method")?.let { value ->
                    when (value) {
                        "get" -> RequestUriMethod.GET
                        "post" -> RequestUriMethod.POST
                        else -> throw RequestValidationError.InvalidRequestUriMethod.asException()
                    }
                }
            when {
                !requestValue.isNullOrEmpty() -> {
                    ensure(requestUriValue == null) {
                        RequestValidationError.InvalidUseOfBothRequestAndRequestUri.asException()
                    }
                    ensure(requestUriMethod == null) {
                        RequestValidationError.InvalidRequestUriMethod.asException()
                    }
                    PassByValue(clientId(), requestValue)
                }
                !requestUriValue.isNullOrEmpty() -> {
                    val requestUri = requestUriValue.asURL().getOrThrow()
                    PassByReference(clientId(), requestUri, requestUriMethod)
                }

                else -> notSecured(uri)
            }
        }

        /**
         * Populates a [Plain] from the query parameters of the given [uri]
         */
        private fun notSecured(uri: Uri): Plain {
            fun jsonObject(p: String): JsonObject? =
                uri.getQueryParameter(p)?.let { Json.parseToJsonElement(it).jsonObject }

            return Plain(
                UnvalidatedRequestObject(
                    responseType = uri.getQueryParameter("response_type"),
                    presentationDefinition = jsonObject("presentation_definition"),
                    presentationDefinitionUri = uri.getQueryParameter("presentation_definition_uri"),
                    dcqlQuery = jsonObject("dcql_query"),
                    scope = uri.getQueryParameter("scope"),
                    nonce = uri.getQueryParameter("nonce"),
                    responseMode = uri.getQueryParameter("response_mode"),
                    clientMetaData = jsonObject("client_metadata"),
                    clientId = uri.getQueryParameter("client_id"),
                    responseUri = uri.getQueryParameter("response_uri"),
                    redirectUri = uri.getQueryParameter("redirect_uri"),
                    state = uri.getQueryParameter("state"),
                ),
            )
        }
    }
}

internal sealed interface FetchedRequest {
    data class Plain(val requestObject: UnvalidatedRequestObject) : FetchedRequest
    data class JwtSecured(val clientId: String, val jwt: SignedJWT) : FetchedRequest
}

internal class DefaultAuthorizationRequestResolver(
    private val siopOpenId4VPConfig: SiopOpenId4VPConfig,
    private val httpKtorHttpClientFactory: KtorHttpClientFactory,
) : AuthorizationRequestResolver {

    override suspend fun resolveRequestUri(uri: String): Resolution =
        httpKtorHttpClientFactory().use { httpClient ->
            resolveRequestUri(httpClient, uri)
        }

    private suspend fun resolveRequestUri(httpClient: HttpClient, uri: String): Resolution {
        val requestFetcher = RequestFetcher(httpClient, siopOpenId4VPConfig)
        val requestAuthenticator = RequestAuthenticator(siopOpenId4VPConfig, httpClient)
        val requestObjectResolver = RequestObjectResolver(siopOpenId4VPConfig, httpClient)

        return try {
            val unvalidatedRequest = UnvalidatedRequest.make(uri).getOrThrow()
            val fetchedRequest = requestFetcher.fetchRequest(unvalidatedRequest)
            val authenticatedRequest = requestAuthenticator.authenticate(fetchedRequest)
            val validatedRequestObject = validateRequestObject(authenticatedRequest)
            val resolved = requestObjectResolver.resolveRequestObject(validatedRequestObject)
            Resolution.Success(resolved)
        } catch (e: AuthorizationRequestException) {
            Resolution.Invalid(e.error)
        } catch (e: ClientRequestException) {
            Resolution.Invalid(HttpError(e))
        }
    }
}
