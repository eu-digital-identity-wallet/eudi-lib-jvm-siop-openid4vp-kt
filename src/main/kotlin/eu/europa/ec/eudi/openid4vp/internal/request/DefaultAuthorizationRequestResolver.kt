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
import eu.europa.ec.eudi.openid4vp.*
import eu.europa.ec.eudi.openid4vp.RequestValidationError.InvalidClientIdScheme
import eu.europa.ec.eudi.openid4vp.internal.request.UnvalidatedRequest.JwtSecured
import eu.europa.ec.eudi.openid4vp.internal.request.UnvalidatedRequest.JwtSecured.PassByReference
import eu.europa.ec.eudi.openid4vp.internal.request.UnvalidatedRequest.JwtSecured.PassByValue
import eu.europa.ec.eudi.openid4vp.internal.request.UnvalidatedRequest.Plain
import io.ktor.client.call.*
import io.ktor.client.request.*
import io.ktor.http.*
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
    @SerialName("client_metadata_uri") val clientMetadataUri: String? = null,
    @SerialName("client_id_scheme") val clientIdScheme: String? = null,
    @Required val nonce: String? = null,
    @SerialName("client_id") val clientId: String? = null,
    @SerialName("response_type") val responseType: String? = null,
    @SerialName("response_mode") val responseMode: String? = null,
    @SerialName("response_uri") val responseUri: String? = null,
    @SerialName("presentation_definition") val presentationDefinition: JsonObject? = null,
    @SerialName("presentation_definition_uri") val presentationDefinitionUri: String? = null, // Not utilized from ISO-23330-4
    @SerialName("redirect_uri") val redirectUri: String? = null,
    val scope: String? = null,
    @SerialName("supported_algorithm") val supportedAlgorithm: String? = null,
    val state: String? = null, // OpenId4VP specific, not utilized from ISO-23330-4
    @SerialName("id_token_type") val idTokenType: String? = null,
)

/**
 * OAUTH2 authorization request
 *
 * This is merely a data carrier structure that doesn't enforce any rules.
 */
private sealed interface UnvalidatedRequest {

    data class Plain(val requestObject: UnvalidatedRequestObject) : UnvalidatedRequest

    /**
     * JWT Secured authorization request (JAR)
     */
    sealed interface JwtSecured : UnvalidatedRequest {
        /**
         * The <em>client_id</em> of the relying party (verifier)
         */
        val clientId: String

        /**
         * A JAR passed by value
         */
        data class PassByValue(override val clientId: String, val jwt: Jwt) : JwtSecured

        /**
         * A JAR passed by reference
         */
        data class PassByReference(override val clientId: String, val jwtURI: URL) : JwtSecured
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

            when {
                !requestValue.isNullOrEmpty() -> PassByValue(clientId(), requestValue)
                !requestUriValue.isNullOrEmpty() ->
                    requestUriValue.asURL()
                        .map { PassByReference(clientId(), it) }
                        .getOrThrow()

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
                    scope = uri.getQueryParameter("scope"),
                    nonce = uri.getQueryParameter("nonce"),
                    responseMode = uri.getQueryParameter("response_mode"),
                    clientIdScheme = uri.getQueryParameter("client_id_scheme"),
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

internal data class AuthenticatedRequestObject(
    val clientIdScheme: SupportedClientIdScheme,
    val requestObject: UnvalidatedRequestObject,
)

internal class DefaultAuthorizationRequestResolver(
    private val siopOpenId4VPConfig: SiopOpenId4VPConfig,
    private val httpClientFactory: KtorHttpClientFactory,
    private val requestObjectResolver: RequestObjectResolver,
) : AuthorizationRequestResolver {

    /**
     * Factory method for creating a [DefaultAuthorizationRequestResolver]
     */
    constructor(
        siopOpenId4VPConfig: SiopOpenId4VPConfig,
        httpClientFactory: KtorHttpClientFactory,
    ) : this(
        siopOpenId4VPConfig,
        httpClientFactory,
        RequestObjectResolver(
            presentationDefinitionResolver = PresentationDefinitionResolver(httpClientFactory),
            clientMetadataValidator = ClientMetaDataValidator(httpClientFactory),
        ),
    )

    private val jarJwtValidator = JarJwtSignatureValidator(siopOpenId4VPConfig, httpClientFactory)

    override suspend fun resolveRequestUri(uri: String): Resolution = try {
        val unvalidatedRequest = UnvalidatedRequest.make(uri).getOrThrow()
        val authenticatedRequestObject = fetchAndAuthenticate(unvalidatedRequest)
        val validatedRequestObject = validateRequestObject(authenticatedRequestObject)
        val resolved = fetchReferences(validatedRequestObject)
        Resolution.Success(resolved)
    } catch (e: AuthorizationRequestException) {
        Resolution.Invalid(e.error)
    }

    private suspend fun fetchAndAuthenticate(request: UnvalidatedRequest): AuthenticatedRequestObject =
        when (request) {
            is Plain -> authenticate(request)
            is JwtSecured -> authenticate(request)
        }

    private suspend fun fetchReferences(r: ValidatedRequestObject): ResolvedRequestObject =
        requestObjectResolver.resolve(siopOpenId4VPConfig, r)

    private fun authenticate(request: Plain): AuthenticatedRequestObject {
        val requestObject = request.requestObject
        fun invalidScheme() = InvalidClientIdScheme(requestObject.clientIdScheme.orEmpty()).asException()
        val clientIdScheme = requestObject.clientIdScheme?.let {
            ClientIdScheme.make(it)?.takeIf(ClientIdScheme::supportsNonJar)
        } ?: throw invalidScheme()

        fun knownClient(s: SupportedClientIdScheme) =
            if (s !is SupportedClientIdScheme.Preregistered) true
            else s.clients.containsKey(requestObject.clientId)

        val supportedClientIdScheme = siopOpenId4VPConfig.supportedClientIdScheme(clientIdScheme)
        val auth = supportedClientIdScheme
            ?.takeIf(::knownClient)
            ?: throw RequestValidationError.UnsupportedClientIdScheme.asException()
        return AuthenticatedRequestObject(auth, requestObject)
    }

    private suspend fun authenticate(request: JwtSecured): AuthenticatedRequestObject {
        suspend fun fetchJwt(request: PassByReference): Jwt =
            httpClientFactory().use { client ->
                client.get(request.jwtURI) {
                    accept(ContentType.parse("application/oauth-authz-req+jwt"))
                }.body<String>()
            }

        val unvalidatedJwt: Jwt = when (request) {
            is PassByValue -> request.jwt
            is PassByReference -> fetchJwt(request)
        }

        val (clientIdScheme, requestObject) = jarJwtValidator.validate(request.clientId, unvalidatedJwt)
        return AuthenticatedRequestObject(clientIdScheme, requestObject)
    }
}

private val OnlyNonJar = listOf(ClientIdScheme.RedirectUri)
private val OnlyJar = listOf(ClientIdScheme.X509_SAN_DNS, ClientIdScheme.X509_SAN_URI, ClientIdScheme.DID)
private val EitherJarOrNoJar = listOf(ClientIdScheme.PreRegistered, ClientIdScheme.EntityId)

internal fun ClientIdScheme.supportsNonJar() = this in OnlyNonJar || this in EitherJarOrNoJar
internal fun ClientIdScheme.supportsJar() = this in OnlyJar || this in EitherJarOrNoJar
