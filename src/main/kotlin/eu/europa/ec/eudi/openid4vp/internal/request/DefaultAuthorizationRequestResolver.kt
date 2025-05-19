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

import com.nimbusds.jose.JWSObject
import com.nimbusds.jose.JWSObjectJSON
import com.nimbusds.jose.util.Base64URL
import com.nimbusds.jose.util.JSONObjectUtils
import com.nimbusds.jwt.JWTClaimsSet
import com.nimbusds.jwt.SignedJWT
import eu.europa.ec.eudi.openid4vp.*
import eu.europa.ec.eudi.openid4vp.internal.ensure
import eu.europa.ec.eudi.openid4vp.internal.jsonSupport
import eu.europa.ec.eudi.openid4vp.internal.request.UnvalidatedRequest.JwtSecured.PassByReference
import eu.europa.ec.eudi.openid4vp.internal.request.UnvalidatedRequest.JwtSecured.PassByValue
import io.ktor.client.*
import io.ktor.http.*
import io.ktor.util.*
import kotlinx.serialization.Required
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.*
import java.net.URI
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
    @SerialName(OpenId4VPSpec.RESPONSE_URI) val responseUri: String? = null,
    @SerialName(OpenId4VPSpec.PRESENTATION_DEFINITION) val presentationDefinition: JsonObject? = null,
    @SerialName(OpenId4VPSpec.PRESENTATION_DEFINITION_URI) val presentationDefinitionUri: String? = null,
    @SerialName(OpenId4VPSpec.DCQL_QUERY) val dcqlQuery: JsonObject? = null,
    @SerialName("redirect_uri") val redirectUri: String? = null,
    @SerialName("scope") val scope: String? = null,
    @SerialName("supported_algorithm") val supportedAlgorithm: String? = null,
    @SerialName("state") val state: String? = null,
    @SerialName("id_token_type") val idTokenType: String? = null,
    @SerialName(OpenId4VPSpec.TRANSACTION_DATA) val transactionData: List<String>? = null,
    @SerialName("verifier_attestations") val verifierAttestations: JsonArray? = null,
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
                    presentationDefinition = jsonObject(OpenId4VPSpec.PRESENTATION_DEFINITION),
                    presentationDefinitionUri = requestParams[OpenId4VPSpec.PRESENTATION_DEFINITION_URI],
                    dcqlQuery = jsonObject(OpenId4VPSpec.DCQL_QUERY),
                    scope = requestParams["scope"],
                    nonce = requestParams["nonce"],
                    responseMode = requestParams["response_mode"],
                    clientMetaData = jsonObject("client_metadata"),
                    clientId = requestParams["client_id"],
                    responseUri = requestParams[OpenId4VPSpec.RESPONSE_URI],
                    redirectUri = requestParams["redirect_uri"],
                    state = requestParams["state"],
                    transactionData = jsonArray(OpenId4VPSpec.TRANSACTION_DATA)?.map { it.jsonPrimitive.content },
                    verifierAttestations = jsonArray("verifier_attestations"),
                ),
            )
        }
    }
}

internal sealed interface FetchedRequest {
    data class Plain(val requestObject: UnvalidatedRequestObject) : FetchedRequest
    data class JwtSecured(val clientId: String, val jwt: SignedJWT) : FetchedRequest
}

internal sealed interface ReceivedRequest {

    data class Unsigned(val requestObject: UnvalidatedRequestObject) : ReceivedRequest

    data class Signed(
        val payload: Base64URL,
        val signatures: List<RequestSignature>,
    ) : ReceivedRequest {

        init {
            require(!signatures.isEmpty()) { "At least one signature is required" }
        }

        companion object {

            /**
             * Decomposes a Nimbus [SignedJWT] into a [ReceivedRequest.Signed] request.
             */
            fun from(signedJwt: SignedJWT): Result<Signed> = runCatching {
                require(signedJwt.state == JWSObject.State.SIGNED) { "JWS is not signed" }
                val header = signedJwt.header.toBase64URL()
                val payload = signedJwt.payload.toBase64URL()
                val signature = signedJwt.signature

                val signatures = listOf(RequestSignature(Header(header), signature))
                Signed(payload, signatures)
            }

            /**
             * Parses an input [JsonObject] representing a JWS in JSON serialization into a [ReceivedRequest.Signed] request.
             */
            fun from(jwsJsonObject: JsonObject): Result<Signed> = runCatching {
                require(jwsJsonObject.containsKey("payload")) { "No payload found for the passed request" }
                require(jwsJsonObject.containsKey("signatures") || jwsJsonObject.containsKey("signature")) {
                    "No signatures found for the passed request"
                }
                val parsed = JWSObjectJSON.parse(jwsJsonObject)
                val signatures = parsed.getSignatures()
                val requestSignatures = signatures?.map {
                    val unprotectedHeader = it.unprotectedHeader?.let {
                        val str = JSONObjectUtils.toJSONString(it.toJSONObject())
                        jsonSupport.decodeFromString<JsonObject>(str)
                    }
                    RequestSignature(
                        header = Header(it.header.toBase64URL(), unprotectedHeader),
                        signature = it.signature,
                    )
                }
                require(requestSignatures != null) { "No signatures found for the passed request" }

                Signed(parsed.payload.toBase64URL(), requestSignatures)
            }
        }
    }
}

internal data class RequestSignature(
    val header: Header,
    val signature: Signature,
)

internal data class Header(
    val protected: Base64URL,
    val unProtected: JsonObject? = null,
)

internal typealias Signature = Base64URL

internal fun ReceivedRequest.Signed.toSignedJwts(): List<SignedJWT> =
    signatures.map {
        SignedJWT.parse("${it.header.protected}.$payload.${it.signature}")
    }

internal fun FetchedRequest.toReceivedRequest(): ReceivedRequest =
    when (this) {
        is FetchedRequest.Plain -> ReceivedRequest.Unsigned(requestObject)
        is FetchedRequest.JwtSecured -> ReceivedRequest.Signed.from(jwt).getOrThrow()
    }

internal class DefaultAuthorizationRequestResolver(
    private val siopOpenId4VPConfig: SiopOpenId4VPConfig,
    private val httpKtorHttpClientFactory: KtorHttpClientFactory,
) : AuthorizationRequestResolver {

    override suspend fun resolveRequestUri(uri: String): Resolution =
        httpKtorHttpClientFactory().use { httpClient ->
            with(httpClient) {
                resolveRequestUri(uri)
            }
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
                authenticateRequest(fetchedRequest.toReceivedRequest())
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
        return requestValidator.validateRequestObject(authenticatedRequest)
    }

    private suspend fun HttpClient.fetchRequest(uri: String): FetchedRequest {
        val unvalidatedRequest = UnvalidatedRequest.make(uri).getOrThrow()
        val requestFetcher = RequestFetcher(this, siopOpenId4VPConfig)
        return requestFetcher.fetchRequest(unvalidatedRequest)
    }

    private suspend fun HttpClient.authenticateRequest(receivedRequest: ReceivedRequest): AuthenticatedRequest {
        val requestAuthenticator = RequestAuthenticator(siopOpenId4VPConfig, this)
        return requestAuthenticator.authenticate(receivedRequest)
    }
}

/**
 * Creates an invalid resolution for errors that manifested while trying to authenticate a Client.
 */
private fun dispatchDetailsOrNull(
    fetchedRequest: FetchedRequest,
    siopOpenId4VPConfig: SiopOpenId4VPConfig,
): ErrorDispatchDetails? =
    when (fetchedRequest) {
        is FetchedRequest.JwtSecured -> fetchedRequest.jwt.jwtClaimsSet.dispatchDetailsOrNull()
        is FetchedRequest.Plain -> dispatchDetailsOrNull(fetchedRequest.requestObject, siopOpenId4VPConfig)
    }

/**
 * Creates an invalid resolution for errors that manifested while trying to resolve the metadata of the Client or while
 * trying to resolve the Authorization Request.
 *
 * Such errors are dispatchable when:
 * * the response mode does not require JARM
 * * the response mode requires JARM and we have resolved Client metadata that contain JARM parameters compatible with
 * the configuration of the Wallet
 */
private fun dispatchDetailsOrNull(
    unvalidatedRequest: UnvalidatedRequestObject,
    siopOpenId4VPConfig: SiopOpenId4VPConfig,
): ErrorDispatchDetails? {
    val responseMode = unvalidatedRequest.responseMode()
    return responseMode?.let {
        val jarmRequirement = unvalidatedRequest.jarmRequirement(siopOpenId4VPConfig, responseMode)
        ErrorDispatchDetails(
            responseMode = responseMode,
            nonce = unvalidatedRequest.nonce,
            state = unvalidatedRequest.state,
            clientId = unvalidatedRequest.clientId?.let { VerifierId.parse(it).getOrNull() },
            jarmRequirement = jarmRequirement.getOrNull(),
        )
    }
}

private fun UnvalidatedRequestObject.jarmRequirement(
    siopOpenId4VPConfig: SiopOpenId4VPConfig,
    responseMode: ResponseMode,
): Result<JarmRequirement?> = runCatching {
    clientMetaData?.let {
        val decodeFromJsonElement = jsonSupport.decodeFromJsonElement<UnvalidatedClientMetaData>(clientMetaData)
        val resolvedClientMetadata = decodeFromJsonElement.let {
            ClientMetaDataValidator.validateClientMetaData(it, responseMode)
        }
        resolvedClientMetadata.let { siopOpenId4VPConfig.jarmRequirement(it) }
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

private fun JWTClaimsSet.responseMode(): ResponseMode? =
    runCatching {
        fun JWTClaimsSet.responseUri(): URL? = getStringClaim(OpenId4VPSpec.RESPONSE_URI)?.let { URL(it) }
        fun JWTClaimsSet.redirectUri(): URI? = getStringClaim("redirect_uri")?.let { URI.create(it) }

        when (getStringClaim("response_mode")) {
            "direct_post" -> responseUri()?.let { ResponseMode.DirectPost(it) }
            "direct_post.jwt" -> responseUri()?.let { ResponseMode.DirectPostJwt(it) }
            "query" -> redirectUri()?.let { ResponseMode.Query(it) }
            "query.jwt" -> redirectUri()?.let { ResponseMode.QueryJwt(it) }
            null, "fragment" -> redirectUri()?.let { ResponseMode.Fragment(it) }
            "fragment.jwt" -> redirectUri()?.let { ResponseMode.FragmentJwt(it) }
            else -> null
        }
    }.getOrNull()

private fun JWTClaimsSet.dispatchDetailsOrNull(): ErrorDispatchDetails? =
    runCatching {
        responseMode()
            ?.takeIf { !it.isJarm() }
            ?.let { responseMode ->
                ErrorDispatchDetails(
                    responseMode = responseMode,
                    nonce = getStringClaim("nonce"),
                    state = getStringClaim("state"),
                    clientId = getStringClaim("client_id")?.let { VerifierId.parse(it).getOrNull() },
                    jarmRequirement = null,
                )
            }
    }.getOrNull()

private fun URI.toKtorUrl(): Url = URLBuilder().takeFrom(this.toString()).build()
