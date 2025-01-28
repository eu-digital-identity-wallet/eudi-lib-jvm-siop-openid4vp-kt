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
import eu.europa.ec.eudi.openid4vp.RequestValidationError.*
import eu.europa.ec.eudi.openid4vp.dcql.DCQL
import eu.europa.ec.eudi.openid4vp.internal.ensure
import eu.europa.ec.eudi.openid4vp.internal.ensureNotNull
import eu.europa.ec.eudi.openid4vp.internal.request.ValidatedRequestObject.*
import eu.europa.ec.eudi.prex.PresentationDefinition
import kotlinx.serialization.SerializationException
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.decodeFromJsonElement
import java.net.MalformedURLException
import java.net.URI
import java.net.URL

internal sealed interface QuerySource {

    @JvmInline
    value class ByPresentationDefinitionSource(
        val value: PresentationDefinitionSource,
    ) : QuerySource

    @JvmInline
    value class ByDCQLQuery(val value: DCQL) : QuerySource

    @JvmInline
    value class ByScope(val value: Scope) : QuerySource
}

internal sealed interface PresentationDefinitionSource {

    /**
     * Presentation definition is given by value (that is embedded to the authorization request)
     * by the verifier
     */
    data class ByValue(val presentationDefinition: PresentationDefinition) : PresentationDefinitionSource

    /**
     * Presentation Definition can be retrieved from the resource at the specified
     * URL, rather than being passed by value.
     * The Wallet will send a GET request without additional parameters.
     * The resource MUST be exposed without a further need to authenticate or authorize
     */
    data class ByReference(val url: URL) : PresentationDefinitionSource
}

/**
 * Represents a request object that has been validated to
 * represent one of the supported requests.
 * Valid in this context, means that the authorization request had the necessary
 * information to represent either
 * - a [SiopAuthentication], or
 * - a [OpenId4VPAuthorization], or
 * - a [SiopOpenId4VPAuthentication]
 *
 */
internal sealed interface ValidatedRequestObject {

    val client: AuthenticatedClient
    val clientMetaData: UnvalidatedClientMetaData?
    val nonce: String
    val responseMode: ResponseMode
    val state: String?

    /**
     * A valid SIOP authentication
     */
    data class SiopAuthentication(
        val idTokenType: List<IdTokenType>,
        override val clientMetaData: UnvalidatedClientMetaData?,
        override val client: AuthenticatedClient,
        override val nonce: String,
        val scope: Scope,
        override val responseMode: ResponseMode,
        override val state: String?,
    ) : ValidatedRequestObject

    /**
     * A valid OpenID4VP authorization
     */
    data class OpenId4VPAuthorization(
        val querySource: QuerySource,
        override val clientMetaData: UnvalidatedClientMetaData?,
        override val client: AuthenticatedClient,
        override val nonce: String,
        override val responseMode: ResponseMode,
        override val state: String?,
        val transactionData: List<String>?,
    ) : ValidatedRequestObject

    /**
     * A valid combined SIOP & OpenID4VP request
     */
    data class SiopOpenId4VPAuthentication(
        val idTokenType: List<IdTokenType>,
        val querySource: QuerySource,
        override val clientMetaData: UnvalidatedClientMetaData?,
        override val client: AuthenticatedClient,
        override val nonce: String,
        val scope: Scope,
        override val responseMode: ResponseMode,
        override val state: String?,
        val transactionData: List<String>?,
    ) : ValidatedRequestObject
}

private val jsonSupport: Json = Json { ignoreUnknownKeys = true }

/**
 * Validates that the given [request] represents a valid and supported [ValidatedRequestObject]
 *
 * @param request The request to validate
 * @return if given [request] is valid returns an appropriate [ValidatedRequestObject]. Otherwise,
 * returns a [failure][Result.Failure]. Validation rules violations are reported using [AuthorizationRequestError]
 * wrapped inside a [specific exception][AuthorizationRequestException]
 */
internal fun validateRequestObject(request: AuthenticatedRequest): ValidatedRequestObject {
    val (client, requestObject) = request
    val scope = requiredScope(requestObject)
    val nonOpenIdScope = with(Scope) { scope.getOrNull()?.items()?.filter { it != OpenId }?.mergeOrNull() }
    val state = requestObject.state
    val nonce = requiredNonce(requestObject)
    val responseType = requiredResponseType(requestObject)
    val responseMode = requiredResponseMode(client, requestObject)
    val clientMetaData = optionalClientMetaData(responseMode, requestObject)
    val idTokenType = optionalIdTokenType(requestObject)
    val transactionData = requestObject.transactionData

    fun idAndVpToken(): SiopOpenId4VPAuthentication {
        val querySource = parseQuerySource(requestObject, nonOpenIdScope)
        return SiopOpenId4VPAuthentication(
            idTokenType,
            querySource,
            clientMetaData,
            client,
            nonce,
            scope.getOrThrow(),
            responseMode,
            state,
            transactionData,
        )
    }

    fun idToken(): SiopAuthentication = SiopAuthentication(
        idTokenType,
        clientMetaData,
        client,
        nonce,
        scope.getOrThrow(),
        responseMode,
        state,
    )

    fun vpToken(): OpenId4VPAuthorization {
        val querySource = parseQuerySource(requestObject, nonOpenIdScope)
        return OpenId4VPAuthorization(
            querySource,
            clientMetaData,
            client,
            nonce,
            responseMode,
            state,
            transactionData,
        )
    }

    return when (responseType) {
        ResponseType.VpAndIdToken -> {
            if (scope.getOrNull()?.contains(Scope.OpenId) == true) idAndVpToken()
            else vpToken()
        }

        ResponseType.IdToken -> idToken()
        ResponseType.VpToken -> vpToken()
    }
}

private fun optionalIdTokenType(unvalidated: UnvalidatedRequestObject): List<IdTokenType> =
    unvalidated.idTokenType
        ?.trim()
        ?.split(" ")
        ?.map { type ->
            when (type) {
                "subject_signed_id_token" -> IdTokenType.SubjectSigned
                "attester_signed_id_token" -> IdTokenType.AttesterSigned
                else -> error("Invalid id_token_type $type")
            }
        }
        ?: emptyList()

private fun requiredResponseMode(
    client: AuthenticatedClient,
    unvalidated: UnvalidatedRequestObject,
): ResponseMode {
    fun requiredRedirectUriAndNotProvidedResponseUri(): URI {
        ensure(unvalidated.responseUri == null) { ResponseUriMustNotBeProvided.asException() }
        // Redirect URI can be omitted in case of RedirectURI
        // and use clientId instead
        val redirectUri = unvalidated.redirectUri?.asURI { InvalidRedirectUri.asException() }?.getOrThrow()
        return when (client) {
            is AuthenticatedClient.RedirectUri -> {
                ensure(redirectUri == null || client.clientId == redirectUri) {
                    InvalidRedirectUri.asException()
                }
                client.clientId
            }

            else -> ensureNotNull(redirectUri) { MissingRedirectUri.asException() }
        }
    }

    fun requiredResponseUriAndNotProvidedRedirectUri(): URL {
        ensure(unvalidated.redirectUri == null) { RedirectUriMustNotBeProvided.asException() }
        val uri = unvalidated.responseUri
        ensureNotNull(uri) { MissingResponseUri.asException() }
        return uri.asURL { InvalidResponseUri.asException() }.getOrThrow()
    }

    val responseMode = when (unvalidated.responseMode) {
        "direct_post" -> requiredResponseUriAndNotProvidedRedirectUri().let { ResponseMode.DirectPost(it) }
        "direct_post.jwt" -> requiredResponseUriAndNotProvidedRedirectUri().let { ResponseMode.DirectPostJwt(it) }
        "query" -> requiredRedirectUriAndNotProvidedResponseUri().let { ResponseMode.Query(it) }
        "query.jwt" -> requiredRedirectUriAndNotProvidedResponseUri().let { ResponseMode.QueryJwt(it) }
        null, "fragment" -> requiredRedirectUriAndNotProvidedResponseUri().let { ResponseMode.Fragment(it) }
        "fragment.jwt" -> requiredRedirectUriAndNotProvidedResponseUri().let { ResponseMode.FragmentJwt(it) }
        else -> throw UnsupportedResponseMode(unvalidated.responseMode).asException()
    }

    val uri = responseMode.uri()
    when (client) {
        is AuthenticatedClient.Preregistered -> Unit
        is AuthenticatedClient.X509SanDns -> ensure(client.clientId == uri.host) {
            UnsupportedResponseMode("$responseMode host doesn't match ${client.clientId}").asException()
        }

        is AuthenticatedClient.X509SanUri -> ensure(client.clientId == uri) {
            UnsupportedResponseMode("$responseMode doesn't match ${client.clientId}").asException()
        }

        is AuthenticatedClient.RedirectUri -> ensure(client.clientId == uri) {
            UnsupportedResponseMode("$responseMode doesn't match ${client.clientId}").asException()
        }

        is AuthenticatedClient.DIDClient -> Unit

        is AuthenticatedClient.Attested -> {
            val allowedUris = when (responseMode) {
                is ResponseMode.Query,
                is ResponseMode.QueryJwt,
                is ResponseMode.Fragment,
                is ResponseMode.FragmentJwt,
                -> client.claims.redirectUris

                is ResponseMode.DirectPost,
                is ResponseMode.DirectPostJwt,
                -> client.claims.responseUris
            }
            if (!allowedUris.isNullOrEmpty()) {
                ensure(uri.toString() in allowedUris) {
                    UnsupportedResponseMode("$responseMode use a URI that is not included in attested URIs $allowedUris").asException()
                }
            }
        }
    }
    return responseMode
}

/**
 * Makes sure that [unvalidated] contains a not-null scope
 *
 * @param unvalidated the request to validate
 * @return the scope or [RequestValidationError.MissingScope]
 */
private fun requiredScope(unvalidated: UnvalidatedRequestObject): Result<Scope> {
    val scope = unvalidated.scope?.let { Scope.make(it) }
    return if (scope != null) Result.success(scope)
    else MissingScope.asFailure()
}

/**
 * Makes sure that [unvalidated] contains a not-null nonce
 *
 * @param unvalidated the request to validate
 * @return the nonce or [RequestValidationError.MissingNonce]
 */
private fun requiredNonce(unvalidated: UnvalidatedRequestObject): String =
    ensureNotNull(unvalidated.nonce) { MissingNonce.asException() }

/**
 * Makes sure that [unvalidated] contains a supported [ResponseType].
 * Function check [UnvalidatedRequestObject.responseType]
 *
 * @param unvalidated the request to validate
 * @return the supported [ResponseType], or [RequestValidationError.MissingResponseType] if the response type is not provided
 * or [RequestValidationError.UnsupportedResponseType] if the response type is not supported
 */
private fun requiredResponseType(unvalidated: UnvalidatedRequestObject): ResponseType =
    when (val rt = unvalidated.responseType?.trim()) {
        "vp_token" -> ResponseType.VpToken
        "vp_token id_token", "id_token vp_token" -> ResponseType.VpAndIdToken
        "id_token" -> ResponseType.IdToken
        null -> throw MissingResponseType.asException()
        else -> throw UnsupportedResponseType(rt).asException()
    }

/**
 * Makes sure that [unvalidated] contains a supported [PresentationDefinitionSource].
 *
 * @param unvalidated the request to validate
 */
private fun parseQuerySource(
    unvalidated: UnvalidatedRequestObject,
    scope: Scope?,
): QuerySource {
    val hasPd = !unvalidated.presentationDefinition.isNullOrEmpty()
    val hasPdUri = !unvalidated.presentationDefinitionUri.isNullOrEmpty()
    val hasDcqlQuery = !unvalidated.dcqlQuery.isNullOrEmpty()
    val hasScope = scope != null

    fun requiredPd() = try {
        checkNotNull(unvalidated.presentationDefinition)
        val pd = jsonSupport.decodeFromJsonElement<PresentationDefinition>(unvalidated.presentationDefinition)
        QuerySource.ByPresentationDefinitionSource(PresentationDefinitionSource.ByValue(pd))
    } catch (t: SerializationException) {
        throw InvalidPresentationDefinition(t).asException()
    }

    fun requiredPdUri() = try {
        checkNotNull(unvalidated.presentationDefinitionUri)
        val pdUri = unvalidated.presentationDefinitionUri.asURL().getOrThrow()
        QuerySource.ByPresentationDefinitionSource(PresentationDefinitionSource.ByReference(pdUri))
    } catch (t: MalformedURLException) {
        throw InvalidPresentationDefinitionUri.asException()
    }

    fun requiredDcqlQuery() = try {
        checkNotNull(unvalidated.dcqlQuery)
        val dcq = jsonSupport.decodeFromJsonElement<DCQL>(unvalidated.dcqlQuery)
        QuerySource.ByDCQLQuery(dcq)
    } catch (t: SerializationException) {
        throw InvalidDigitalCredentialsQuery(t).asException()
    }

    fun requiredScope() = QuerySource.ByScope(checkNotNull(scope))

    val querySourceCount = listOf(hasPd, hasPdUri, hasDcqlQuery, hasScope).count { it }

    return when {
        querySourceCount > 1 -> throw MultipleQuerySources.asException()
        hasDcqlQuery -> requiredDcqlQuery()
        hasPd -> requiredPd()
        hasPdUri -> requiredPdUri()
        hasScope -> requiredScope()
        else -> throw MissingQuerySource.asException()
    }
}

private fun optionalClientMetaData(
    responseMode: ResponseMode,
    unvalidated: UnvalidatedRequestObject,
): UnvalidatedClientMetaData? {
    val hasCMD = !unvalidated.clientMetaData.isNullOrEmpty()

    fun requiredClientMetaData(): UnvalidatedClientMetaData {
        checkNotNull(unvalidated.clientMetaData)
        return jsonSupport.decodeFromJsonElement(unvalidated.clientMetaData)
    }

    fun required() = when (responseMode) {
        is ResponseMode.DirectPost -> false
        is ResponseMode.DirectPostJwt -> true
        is ResponseMode.Fragment -> false
        is ResponseMode.FragmentJwt -> true
        is ResponseMode.Query -> false
        is ResponseMode.QueryJwt -> true
    }

    return when {
        hasCMD -> requiredClientMetaData()
        else -> {
            ensure(!required()) {
                InvalidClientMetaData("Missing client metadata").asException()
            }
            null
        }
    }
}

private fun ResponseMode.uri(): URI = when (this) {
    is ResponseMode.DirectPost -> responseURI.toURI()
    is ResponseMode.DirectPostJwt -> responseURI.toURI()
    is ResponseMode.Fragment -> redirectUri
    is ResponseMode.FragmentJwt -> redirectUri
    is ResponseMode.Query -> redirectUri
    is ResponseMode.QueryJwt -> redirectUri
}

private enum class ResponseType {
    VpToken,
    IdToken,
    VpAndIdToken,
}
