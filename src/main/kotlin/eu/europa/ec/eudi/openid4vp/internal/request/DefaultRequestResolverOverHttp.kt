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
import eu.europa.ec.eudi.openid4vp.internal.JwsJson
import eu.europa.ec.eudi.openid4vp.internal.decodePayloadAs
import eu.europa.ec.eudi.openid4vp.internal.ensure
import eu.europa.ec.eudi.openid4vp.internal.jsonSupport
import eu.europa.ec.eudi.openid4vp.internal.request.UnvalidatedRequest.JwtSecured.PassByReference
import eu.europa.ec.eudi.openid4vp.internal.request.UnvalidatedRequest.JwtSecured.PassByValue
import io.ktor.client.*
import io.ktor.http.*
import io.ktor.util.*
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.*
import java.net.URI
import java.net.URL

@Serializable
@JvmInline
internal value class VerifierInfoTO(val value: JsonArray) {
    init {
        require(value.isNotEmpty())
        require(value.all { it is JsonObject })
    }

    override fun toString(): String = value.toString()

    val values: List<JsonObject>
        get() = value.map { it.jsonObject }
}

@Serializable
@JvmInline
internal value class TransactionDataTO(val value: JsonArray) {
    init {
        require(value.isNotEmpty())
        require(value.all { it is JsonPrimitive && it.isString })
    }

    override fun toString(): String = value.toString()

    val values: List<String>
        get() = value.map { it.jsonPrimitive.content }
}

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
            val requestParams = with(URI.create(uriStr)) {
                toKtorUrl().parameters.toMap().mapValues { it.value.first() }
            }

            fun clientId(): String =
                requestParams["client_id"]
                    ?: throw RequestValidationError.MissingClientId.asException()

            val requestValue = requestParams["request"]
            val requestUriValue = requestParams["request_uri"]
            val requestUriMethod =
                requestParams["request_uri_method"]?.let { value ->
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

                else -> notSecured(requestParams)
            }
        }

        /**
         * Populates a [Plain] from the request parameters of an authorization request
         */
        private fun notSecured(requestParams: Map<String, String?>): Plain {
            fun jsonObject(p: String): JsonObject? =
                requestParams[p]?.let { Json.parseToJsonElement(it).jsonObject }

            fun jsonArray(p: String): JsonArray? =
                requestParams[p]?.let { Json.parseToJsonElement(it).jsonArray }

            return Plain(
                UnvalidatedRequestObject(
                    responseType = requestParams["response_type"],
                    dcqlQuery = jsonObject(OpenId4VPSpec.DCQL_QUERY),
                    scope = requestParams["scope"],
                    nonce = requestParams["nonce"],
                    responseMode = requestParams["response_mode"],
                    clientMetaData = jsonObject("client_metadata"),
                    clientId = requestParams["client_id"],
                    responseUri = requestParams[OpenId4VPSpec.RESPONSE_URI],
                    redirectUri = requestParams["redirect_uri"],
                    state = requestParams["state"],
                    transactionData = jsonArray(OpenId4VPSpec.TRANSACTION_DATA)?.let { TransactionDataTO(it) },
                    verifierInfo = jsonArray(OpenId4VPSpec.VERIFIER_INFO)?.let { VerifierInfoTO(it) },
                ),
            )
        }
    }
}

internal class DefaultRequestResolverOverHttp(
    private val siopOpenId4VPConfig: SiopOpenId4VPConfig,
    private val httpClient: HttpClient,
) : AuthorizationRequestOverHttpResolver {

    override suspend fun resolveRequestUri(uri: String): Resolution =
        with(httpClient) {
            resolveRequestUri(uri)
        }

    private suspend fun HttpClient.resolveRequestUri(uri: String): Resolution {
        val fetchedRequest =
            try {
                fetchRequest(uri)
            } catch (e: AuthorizationRequestException) {
                return Resolution.Invalid.nonDispatchable(e.error)
            }

        val authenticatedRequest =
            try {
                authenticateRequest(fetchedRequest)
            } catch (e: AuthorizationRequestException) {
                val dispatchDetails =
                    when (siopOpenId4VPConfig.errorDispatchPolicy) {
                        ErrorDispatchPolicy.AllClients -> dispatchDetailsOrNull(fetchedRequest, siopOpenId4VPConfig)
                        ErrorDispatchPolicy.OnlyAuthenticatedClients -> null
                    }
                return Resolution.Invalid(e.error, dispatchDetails)
            }

        val resolved =
            try {
                validateRequestObject(authenticatedRequest)
            } catch (e: AuthorizationRequestException) {
                val dispatchDetails = dispatchDetailsOrNull(authenticatedRequest.requestObject, siopOpenId4VPConfig)
                return Resolution.Invalid(e.error, dispatchDetails)
            }

        return Resolution.Success(resolved)
    }

    private fun validateRequestObject(authenticatedRequest: AuthenticatedRequest): ResolvedRequestObject {
        val requestValidator = RequestObjectValidator(siopOpenId4VPConfig)
        return requestValidator.validateHttpRequestObject(authenticatedRequest)
    }

    private suspend fun HttpClient.fetchRequest(uri: String): ReceivedRequest {
        val unvalidatedRequest = UnvalidatedRequest.make(uri).getOrThrow()
        val requestFetcher = RequestFetcher(this, siopOpenId4VPConfig)
        return requestFetcher.fetchRequest(unvalidatedRequest)
    }

    private suspend fun HttpClient.authenticateRequest(receivedRequest: ReceivedRequest): AuthenticatedRequest {
        val requestAuthenticator = RequestAuthenticator(siopOpenId4VPConfig, this)
        return requestAuthenticator.authenticateRequestOverHttp(receivedRequest)
    }
}

/**
 * Creates an invalid resolution for errors that manifested while trying to authenticate a Client.
 */
private fun dispatchDetailsOrNull(
    fetchedRequest: ReceivedRequest,
    siopOpenId4VPConfig: SiopOpenId4VPConfig,
): ErrorDispatchDetails? =
    when (fetchedRequest) {
        is ReceivedRequest.Signed -> dispatchDetailsOrNull(fetchedRequest.jwsJson, siopOpenId4VPConfig)
        is ReceivedRequest.Unsigned -> dispatchDetailsOrNull(fetchedRequest.requestObject, siopOpenId4VPConfig)
    }

/**
 * Creates an invalid resolution for errors that manifested while trying to resolve the metadata of the Client or while
 * trying to resolve the Authorization Request.
 *
 * Such errors are dispatchable when:
 * * the response mode does not require encryption
 * * the response mode requires encryption, and we have resolved Client metadata that contains encryption parameters compatible with
 * the configuration of the Wallet
 */
private fun dispatchDetailsOrNull(
    unvalidatedRequest: UnvalidatedRequestObject,
    siopOpenId4VPConfig: SiopOpenId4VPConfig,
): ErrorDispatchDetails? {
    return unvalidatedRequest.responseMode()?.let { responseMode ->
        val responseEncryptionSpecification =
            unvalidatedRequest.responseEncryptionSpecification(siopOpenId4VPConfig, responseMode)
        ErrorDispatchDetails(
            responseMode = responseMode,
            nonce = unvalidatedRequest.nonce,
            state = unvalidatedRequest.state,
            clientId = unvalidatedRequest.clientId?.let { VerifierId.parse(it).getOrNull() },
            responseEncryptionSpecification = responseEncryptionSpecification.getOrNull(),
        )
    }
}

private fun UnvalidatedRequestObject.responseEncryptionSpecification(
    siopOpenId4VPConfig: SiopOpenId4VPConfig,
    responseMode: ResponseMode,
): Result<ResponseEncryptionSpecification?> = runCatching {
    clientMetaData?.let {
        val decodeFromJsonElement = jsonSupport.decodeFromJsonElement<UnvalidatedClientMetaData>(clientMetaData)
        val validatedClientMetadata = decodeFromJsonElement.let {
            ClientMetaDataValidator.validateClientMetaData(
                it,
                responseMode,
                null,
                siopOpenId4VPConfig.responseEncryptionConfiguration,
                siopOpenId4VPConfig.vpConfiguration.vpFormatsSupported,
            )
        }
        validatedClientMetadata.responseEncryptionSpecification
    }
}

private fun UnvalidatedRequestObject.responseMode(): ResponseMode? {
    fun UnvalidatedRequestObject.responseUri(): URL? =
        responseUri?.let {
            runCatching { URL(it) }.getOrNull()
        }

    fun UnvalidatedRequestObject.redirectUri(): URI? =
        redirectUri?.let {
            runCatching { URI.create(it) }.getOrNull()
        }

    return when (responseMode) {
        "direct_post" -> responseUri()?.let { ResponseMode.DirectPost(it) }
        "direct_post.jwt" -> responseUri()?.let { ResponseMode.DirectPostJwt(it) }
        "query" -> redirectUri()?.let { ResponseMode.Query(it) }
        "query.jwt" -> redirectUri()?.let { ResponseMode.QueryJwt(it) }
        null, "fragment" -> redirectUri()?.let { ResponseMode.Fragment(it) }
        "fragment.jwt" -> redirectUri()?.let { ResponseMode.FragmentJwt(it) }
        else -> null
    }
}

private fun dispatchDetailsOrNull(
    jwsJson: JwsJson,
    siopOpenId4VPConfig: SiopOpenId4VPConfig,
): ErrorDispatchDetails? =
    runCatching {
        dispatchDetailsOrNull(
            jwsJson.decodePayloadAs<UnvalidatedRequestObject>(),
            siopOpenId4VPConfig,
        )
    }.getOrNull()

private fun URI.toKtorUrl(): Url = URLBuilder().takeFrom(this.toString()).build()
