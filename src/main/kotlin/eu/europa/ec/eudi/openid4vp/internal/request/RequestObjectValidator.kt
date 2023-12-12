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
import eu.europa.ec.eudi.openid4vp.internal.mapError
import eu.europa.ec.eudi.openid4vp.internal.request.ValidatedRequestObject.*
import eu.europa.ec.eudi.openid4vp.internal.success
import eu.europa.ec.eudi.prex.PresentationDefinition
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.decodeFromJsonElement
import java.net.URI
import java.net.URL

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

    /**
     * When a presentation definition is pre-agreed between wallet and verifier, using
     * a specific [scope]. In this case, verifier doesn't communicate the presentation definition
     * neither [by value][ByValue] nor by [ByReference]. Rather, the wallet
     * has been configured (via a specific scope) with a well-known definition
     */
    data class Implied(val scope: Scope) : PresentationDefinitionSource
}

internal sealed interface ClientMetaDataSource {
    data class ByValue(val metaData: UnvalidatedClientMetaData) : ClientMetaDataSource
    data class ByReference(val url: URL) : ClientMetaDataSource
}

/**
 * Represents a [RequestObject] that has been validated to
 * represent one of the supported requests.
 * Valid in this context, means that the [AuthorizationRequest] had the necessary
 * information to represent either
 * - a [SiopAuthentication], or
 * - a [OpenId4VPAuthorization], or
 * - a [SiopOpenId4VPAuthentication]
 *
 * @see RequestObjectValidator for the validation rules implemented
 */
internal sealed interface ValidatedRequestObject {

    val clientId: String
    val clientMetaDataSource: ClientMetaDataSource?
    val nonce: String
    val responseMode: ResponseMode
    val state: String

    /**
     * A valid SIOP authentication
     */
    data class SiopAuthentication(
        val idTokenType: List<IdTokenType>,
        override val clientMetaDataSource: ClientMetaDataSource?,
        override val clientId: String,
        override val nonce: String,
        val scope: Scope,
        override val responseMode: ResponseMode,
        override val state: String,
    ) : ValidatedRequestObject

    /**
     * A valid OpenID4VP authorization
     */
    data class OpenId4VPAuthorization(
        val presentationDefinitionSource: PresentationDefinitionSource,
        override val clientMetaDataSource: ClientMetaDataSource?,
        override val clientId: String,
        override val nonce: String,
        override val responseMode: ResponseMode,
        override val state: String,
    ) : ValidatedRequestObject

    /**
     * A valid combined SIOP & OpenID4VP request
     */
    data class SiopOpenId4VPAuthentication(
        val idTokenType: List<IdTokenType>,
        val presentationDefinitionSource: PresentationDefinitionSource,
        override val clientMetaDataSource: ClientMetaDataSource?,
        override val clientId: String,
        override val nonce: String,
        val scope: Scope,
        override val responseMode: ResponseMode,
        override val state: String,
    ) : ValidatedRequestObject
}

internal object RequestObjectValidator {

    /**
     * Validates that the given [authorizationRequest] represents a valid and supported [ValidatedRequestObject]
     *
     * @param authorizationRequest The request to validate
     * @return if given [authorizationRequest] is valid returns an appropriate [ValidatedRequestObject]. Otherwise,
     * returns a [failure][Result.Failure]. Validation rules violations are reported using [AuthorizationRequestError]
     * wrapped inside a [specific exception][AuthorizationRequestException]
     */
    fun validate(
        supportedClientIdScheme: SupportedClientIdScheme,
        authorizationRequest: RequestObject,
    ): ValidatedRequestObject {
        fun scope() = requiredScope(authorizationRequest)
        val state = requiredState(authorizationRequest).getOrThrow()
        val nonce = requiredNonce(authorizationRequest).getOrThrow()
        val responseType = requiredResponseType(authorizationRequest).getOrThrow()
        val responseMode = requiredResponseMode(authorizationRequest).getOrThrow()
        val clientId = validClientId(supportedClientIdScheme, authorizationRequest, responseMode).getOrThrow()
        val presentationDefinitionSource =
            optionalPresentationDefinitionSource(authorizationRequest, responseType) { scope().getOrNull() }
        val clientMetaDataSource = optionalClientMetaDataSource(authorizationRequest).getOrThrow()
        val idTokenType = optionalIdTokenType(authorizationRequest).getOrThrow()

        fun idAndVpToken() = SiopOpenId4VPAuthentication(
            idTokenType,
            presentationDefinitionSource.getOrThrow()
                ?: throw IllegalStateException("Presentation definition missing"),
            clientMetaDataSource,
            clientId,
            nonce,
            scope().getOrThrow(),
            responseMode,
            state,
        )

        fun idToken() = SiopAuthentication(
            idTokenType,
            clientMetaDataSource,
            clientId,
            nonce,
            scope().getOrThrow(),
            responseMode,
            state,
        )

        fun vpToken() = OpenId4VPAuthorization(
            presentationDefinitionSource.getOrThrow()
                ?: throw IllegalStateException("Presentation definition missing"),
            clientMetaDataSource,
            clientId,
            nonce,
            responseMode,
            state,
        )

        @Suppress("ktlint")
        return when (responseType) {
            ResponseType.VpAndIdToken -> idAndVpToken()
            ResponseType.IdToken -> idToken()
            ResponseType.VpToken ->
                // If scope is defined and its value is "openid" then id token must also be returned
                if (scope().getOrNull()?.value == "openid") idAndVpToken()
                else vpToken()
        }
    }

    private fun optionalPresentationDefinitionSource(
        authorizationRequest: RequestObject,
        responseType: ResponseType,
        scopeProvider: () -> Scope?,
    ): Result<PresentationDefinitionSource?> = when (responseType) {
        ResponseType.VpToken, ResponseType.VpAndIdToken ->
            parsePresentationDefinitionSource(authorizationRequest, scopeProvider())

        ResponseType.IdToken -> Result.success(null)
    }

    private fun optionalIdTokenType(unvalidated: RequestObject): Result<List<IdTokenType>> = runCatching {
        unvalidated.idTokenType
            ?.trim()
            ?.split(" ")
            ?.map {
                when (it) {
                    "subject_signed_id_token" -> IdTokenType.SubjectSigned
                    "attester_signed_id_token" -> IdTokenType.AttesterSigned
                    else -> error("Invalid id_token_type $it")
                }
            }
            ?: emptyList()
    }

    private fun requiredResponseMode(unvalidated: RequestObject): Result<ResponseMode> {
        fun requiredRedirectUriAndNotProvidedResponseUri(): Result<URI> =
            if (unvalidated.responseUri != null) {
                RequestValidationError.ResponseUriMustNotBeProvided.asFailure()
            } else {
                when (val uri = unvalidated.redirectUri) {
                    null -> RequestValidationError.MissingRedirectUri.asFailure()
                    else -> uri.asURI { RequestValidationError.InvalidRedirectUri.asException() }
                }
            }

        fun requiredResponseUriAndNotProvidedRedirectUri(): Result<URL> =
            if (unvalidated.redirectUri != null) RequestValidationError.RedirectUriMustNotBeProvided.asFailure()
            else when (val uri = unvalidated.responseUri) {
                null -> RequestValidationError.MissingResponseUri.asFailure()
                else -> uri.asURL { RequestValidationError.InvalidResponseUri.asException() }
            }

        return when (unvalidated.responseMode) {
            "direct_post" -> requiredResponseUriAndNotProvidedRedirectUri().map { ResponseMode.DirectPost(it) }
            "direct_post.jwt" -> requiredResponseUriAndNotProvidedRedirectUri().map { ResponseMode.DirectPostJwt(it) }
            "query" -> requiredRedirectUriAndNotProvidedResponseUri().map { ResponseMode.Query(it) }
            "query.jwt" -> requiredRedirectUriAndNotProvidedResponseUri().map { ResponseMode.QueryJwt(it) }
            null, "fragment" -> requiredRedirectUriAndNotProvidedResponseUri().map { ResponseMode.Fragment(it) }
            "fragment.jwt" -> requiredRedirectUriAndNotProvidedResponseUri().map { ResponseMode.Fragment(it) }
            else -> RequestValidationError.UnsupportedResponseMode(unvalidated.responseMode).asFailure()
        }
    }

    /**
     * Makes sure that [unvalidated] contains a not-null/not-blank state value
     *
     * @param unvalidated the request to validate
     * @return the state or [RequestValidationError.MissingState]
     */
    @Suppress("ktlint")
    private fun requiredState(unvalidated: RequestObject): Result<String> =
        if (!unvalidated.state.isNullOrBlank()) unvalidated.state.success()
        else RequestValidationError.MissingState.asFailure()

    /**
     * Makes sure that [unvalidated] contains a not-null scope
     *
     * @param unvalidated the request to validate
     * @return the scope or [RequestValidationError.MissingScope]
     */
    private fun requiredScope(unvalidated: RequestObject): Result<Scope> {
        val scope = unvalidated.scope?.let { Scope.make(it) }
        return scope?.success() ?: RequestValidationError.MissingScope.asFailure()
    }

    /**
     * Makes sure that [unvalidated] contains a not-null nonce
     *
     * @param unvalidated the request to validate
     * @return the nonce or [RequestValidationError.MissingNonce]
     */
    private fun requiredNonce(unvalidated: RequestObject): Result<String> =
        unvalidated.nonce?.success() ?: RequestValidationError.MissingNonce.asFailure()

    /**
     * Makes sure that [unvalidated] contains a supported [ResponseType].
     * Function check [RequestObject.responseType]
     *
     * @param unvalidated the request to validate
     * @return the supported [ResponseType], or [RequestValidationError.MissingResponseType] if the response type is not provided
     * or [RequestValidationError.UnsupportedResponseType] if the response type is not supported
     */
    private fun requiredResponseType(unvalidated: RequestObject): Result<ResponseType> =
        when (val rt = unvalidated.responseType?.trim()) {
            "vp_token" -> ResponseType.VpToken.success()
            "vp_token id_token", "id_token vp_token" -> ResponseType.VpAndIdToken.success()
            "id_token" -> ResponseType.IdToken.success()
            null -> RequestValidationError.MissingResponseType.asFailure()
            else -> RequestValidationError.UnsupportedResponseType(rt).asFailure()
        }

    /**
     * Makes sure that [unvalidated] contains a supported [PresentationDefinitionSource].
     *
     * @param unvalidated the request to validate
     */
    private fun parsePresentationDefinitionSource(
        unvalidated: RequestObject,
        scope: Scope?,
    ): Result<PresentationDefinitionSource> {
        val hasPd = !unvalidated.presentationDefinition.isNullOrEmpty()
        val hasPdUri = !unvalidated.presentationDefinitionUri.isNullOrEmpty()
        val hasScope = null != scope
        val json = Json { ignoreUnknownKeys = true }

        fun requiredPd() = runCatching {
            val pd = runCatching {
                json.decodeFromJsonElement<PresentationDefinition>(unvalidated.presentationDefinition!!)
            }.mapError { RequestValidationError.InvalidPresentationDefinition(it).asException() }.getOrThrow()
            PresentationDefinitionSource.ByValue(pd)
        }

        fun requiredPdUri() = runCatching {
            val pdUri = unvalidated.presentationDefinitionUri!!.asURL().getOrThrow()
            PresentationDefinitionSource.ByReference(pdUri)
        }.mapError { RequestValidationError.InvalidPresentationDefinitionUri.asException() }

        fun requiredScope() = PresentationDefinitionSource.Implied(scope!!).success()

        return when {
            hasPd && !hasPdUri -> requiredPd()
            !hasPd && hasPdUri -> requiredPdUri()
            hasScope -> requiredScope()
            else -> RequestValidationError.MissingPresentationDefinition.asFailure()
        }
    }

    private fun validClientId(
        supportedClientIdScheme: SupportedClientIdScheme,
        unvalidated: RequestObject,
        responseMode: ResponseMode,
    ): Result<String> = runCatching {
        val clientId = unvalidated.clientId ?: throw RequestValidationError.MissingClientId.asException()
        val uri = responseMode.uri()
        clientId.takeIf {
            when (supportedClientIdScheme) {
                is SupportedClientIdScheme.Preregistered -> true
                is SupportedClientIdScheme.X509SanDns -> it == uri.host
                is SupportedClientIdScheme.X509SanUri, SupportedClientIdScheme.RedirectUri -> it == uri.toString()
            }
        } ?: throw RequestValidationError.InvalidClientId.asException()
    }

    private fun optionalClientMetaDataSource(unvalidated: RequestObject): Result<ClientMetaDataSource?> {
        val hasCMD = !unvalidated.clientMetaData.isNullOrEmpty()
        val hasCMDUri = !unvalidated.clientMetadataUri.isNullOrEmpty()

        fun requiredClientMetaData() = runCatching {
            ClientMetaDataSource.ByValue(Json.decodeFromJsonElement<UnvalidatedClientMetaData>(unvalidated.clientMetaData!!))
        }

        fun requiredClientMetaDataUri() = runCatching {
            val uri =
                unvalidated.clientMetadataUri!!.asURL { RequestValidationError.InvalidClientMetaDataUri.asException() }
                    .getOrThrow()
            ClientMetaDataSource.ByReference(uri)
        }

        return when {
            hasCMD && !hasCMDUri -> requiredClientMetaData()
            !hasCMD && hasCMDUri -> requiredClientMetaDataUri()
            hasCMD && hasCMDUri -> RequestValidationError.OneOfClientMedataOrUri.asFailure()
            else -> Result.success(null)
        }
    }
}
