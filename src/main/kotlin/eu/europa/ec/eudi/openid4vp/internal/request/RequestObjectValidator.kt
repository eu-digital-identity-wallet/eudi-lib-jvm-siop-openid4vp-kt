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
import eu.europa.ec.eudi.openid4vp.internal.request.ValidatedRequestObject.*
import eu.europa.ec.eudi.prex.PresentationDefinition
import kotlinx.serialization.SerializationException
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.decodeFromJsonElement
import java.net.MalformedURLException
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

    private val jsonSupport: Json = Json { ignoreUnknownKeys = true }

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
        val state = requiredState(authorizationRequest)
        val nonce = requiredNonce(authorizationRequest)
        val responseType = requiredResponseType(authorizationRequest)
        val responseMode = requiredResponseMode(supportedClientIdScheme, authorizationRequest)
        val clientId = validClientId(supportedClientIdScheme, authorizationRequest, responseMode)
        val presentationDefinitionSource =
            optionalPresentationDefinitionSource(authorizationRequest, responseType) { scope().getOrNull() }
        val clientMetaDataSource = optionalClientMetaDataSource(authorizationRequest)
        val idTokenType = optionalIdTokenType(authorizationRequest)

        fun idAndVpToken() = SiopOpenId4VPAuthentication(
            idTokenType,
            checkNotNull(presentationDefinitionSource) { "Presentation definition missing" },
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
            checkNotNull(presentationDefinitionSource) { "Presentation definition missing" },
            clientMetaDataSource,
            clientId,
            nonce,
            responseMode,
            state,
        )

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
    ): PresentationDefinitionSource? = when (responseType) {
        ResponseType.VpToken, ResponseType.VpAndIdToken ->
            parsePresentationDefinitionSource(authorizationRequest, scopeProvider())

        ResponseType.IdToken -> null
    }

    private fun optionalIdTokenType(unvalidated: RequestObject): List<IdTokenType> =
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
        supportedClientIdScheme: SupportedClientIdScheme,
        unvalidated: RequestObject,
    ): ResponseMode {
        fun requiredRedirectUriAndNotProvidedResponseUri(): URI =
            if (unvalidated.responseUri != null) throw RequestValidationError.ResponseUriMustNotBeProvided.asException()
            else {
                // Redirect URI can be omitted in case of RedirectURI
                // and use clientId instead
                val uri = unvalidated.redirectUri
                    ?: if (supportedClientIdScheme is SupportedClientIdScheme.RedirectUri) unvalidated.clientId else null
                when (uri) {
                    null -> throw RequestValidationError.MissingRedirectUri.asException()
                    else -> uri.asURI { RequestValidationError.InvalidRedirectUri.asException() }.getOrThrow()
                }
            }

        fun requiredResponseUriAndNotProvidedRedirectUri(): URL =
            if (unvalidated.redirectUri != null) throw RequestValidationError.RedirectUriMustNotBeProvided.asException()
            else when (val uri = unvalidated.responseUri) {
                null -> throw RequestValidationError.MissingResponseUri.asException()
                else -> uri.asURL { RequestValidationError.InvalidResponseUri.asException() }.getOrThrow()
            }

        return when (unvalidated.responseMode) {
            "direct_post" -> requiredResponseUriAndNotProvidedRedirectUri().let { ResponseMode.DirectPost(it) }
            "direct_post.jwt" -> requiredResponseUriAndNotProvidedRedirectUri().let { ResponseMode.DirectPostJwt(it) }
            "query" -> requiredRedirectUriAndNotProvidedResponseUri().let { ResponseMode.Query(it) }
            "query.jwt" -> requiredRedirectUriAndNotProvidedResponseUri().let { ResponseMode.QueryJwt(it) }
            null, "fragment" -> requiredRedirectUriAndNotProvidedResponseUri().let { ResponseMode.Fragment(it) }
            "fragment.jwt" -> requiredRedirectUriAndNotProvidedResponseUri().let { ResponseMode.Fragment(it) }
            else -> throw RequestValidationError.UnsupportedResponseMode(unvalidated.responseMode).asException()
        }
    }

    /**
     * Makes sure that [unvalidated] contains a not-null/not-blank state value
     *
     * @param unvalidated the request to validate
     * @return the state or [RequestValidationError.MissingState]
     */
    private fun requiredState(unvalidated: RequestObject): String =
        if (!unvalidated.state.isNullOrBlank()) unvalidated.state
        else throw RequestValidationError.MissingState.asException()

    /**
     * Makes sure that [unvalidated] contains a not-null scope
     *
     * @param unvalidated the request to validate
     * @return the scope or [RequestValidationError.MissingScope]
     */
    private fun requiredScope(unvalidated: RequestObject): Result<Scope> {
        val scope = unvalidated.scope?.let { Scope.make(it) }
        return if (scope != null) Result.success(scope)
        else RequestValidationError.MissingScope.asFailure()
    }

    /**
     * Makes sure that [unvalidated] contains a not-null nonce
     *
     * @param unvalidated the request to validate
     * @return the nonce or [RequestValidationError.MissingNonce]
     */
    private fun requiredNonce(unvalidated: RequestObject): String =
        unvalidated.nonce ?: throw RequestValidationError.MissingNonce.asException()

    /**
     * Makes sure that [unvalidated] contains a supported [ResponseType].
     * Function check [RequestObject.responseType]
     *
     * @param unvalidated the request to validate
     * @return the supported [ResponseType], or [RequestValidationError.MissingResponseType] if the response type is not provided
     * or [RequestValidationError.UnsupportedResponseType] if the response type is not supported
     */
    private fun requiredResponseType(unvalidated: RequestObject): ResponseType =
        when (val rt = unvalidated.responseType?.trim()) {
            "vp_token" -> ResponseType.VpToken
            "vp_token id_token", "id_token vp_token" -> ResponseType.VpAndIdToken
            "id_token" -> ResponseType.IdToken
            null -> throw RequestValidationError.MissingResponseType.asException()
            else -> throw RequestValidationError.UnsupportedResponseType(rt).asException()
        }

    /**
     * Makes sure that [unvalidated] contains a supported [PresentationDefinitionSource].
     *
     * @param unvalidated the request to validate
     */
    private fun parsePresentationDefinitionSource(
        unvalidated: RequestObject,
        scope: Scope?,
    ): PresentationDefinitionSource {
        val hasPd = !unvalidated.presentationDefinition.isNullOrEmpty()
        val hasPdUri = !unvalidated.presentationDefinitionUri.isNullOrEmpty()
        val hasScope = null != scope

        fun requiredPd() = try {
            checkNotNull(unvalidated.presentationDefinition)
            val pd = jsonSupport.decodeFromJsonElement<PresentationDefinition>(unvalidated.presentationDefinition)
            PresentationDefinitionSource.ByValue(pd)
        } catch (t: SerializationException) {
            throw RequestValidationError.InvalidPresentationDefinition(t).asException()
        }

        fun requiredPdUri() = try {
            checkNotNull(unvalidated.presentationDefinitionUri)
            val pdUri = unvalidated.presentationDefinitionUri.asURL().getOrThrow()
            PresentationDefinitionSource.ByReference(pdUri)
        } catch (t: MalformedURLException) {
            throw RequestValidationError.InvalidPresentationDefinitionUri.asException()
        }

        fun requiredScope() = PresentationDefinitionSource.Implied(scope!!)

        return when {
            hasPd && !hasPdUri -> requiredPd()
            !hasPd && hasPdUri -> requiredPdUri()
            hasScope -> requiredScope()
            else -> throw RequestValidationError.MissingPresentationDefinition.asException()
        }
    }

    private fun validClientId(
        supportedClientIdScheme: SupportedClientIdScheme,
        unvalidated: RequestObject,
        responseMode: ResponseMode,
    ): String {
        val clientId = unvalidated.clientId ?: throw RequestValidationError.MissingClientId.asException()
        val uri = responseMode.uri()
        fun checkWithScheme() = when (supportedClientIdScheme) {
            is SupportedClientIdScheme.Preregistered -> true
            is SupportedClientIdScheme.X509SanDns -> clientId == uri.host
            is SupportedClientIdScheme.X509SanUri, SupportedClientIdScheme.RedirectUri -> clientId == uri.toString()
        }
        return if (checkWithScheme()) clientId
        else throw RequestValidationError.InvalidClientId.asException()
    }

    private fun optionalClientMetaDataSource(unvalidated: RequestObject): ClientMetaDataSource? {
        val hasCMD = !unvalidated.clientMetaData.isNullOrEmpty()
        val hasCMDUri = !unvalidated.clientMetadataUri.isNullOrEmpty()

        fun requiredClientMetaData(): ClientMetaDataSource.ByValue {
            checkNotNull(unvalidated.clientMetaData)
            return ClientMetaDataSource.ByValue(jsonSupport.decodeFromJsonElement(unvalidated.clientMetaData))
        }

        fun requiredClientMetaDataUri(): ClientMetaDataSource.ByReference {
            checkNotNull(unvalidated.clientMetadataUri)
            val uri = unvalidated.clientMetadataUri
                .asURL { RequestValidationError.InvalidClientMetaDataUri.asException() }
                .getOrThrow()
            return ClientMetaDataSource.ByReference(uri)
        }

        return when {
            hasCMD && !hasCMDUri -> requiredClientMetaData()
            !hasCMD && hasCMDUri -> requiredClientMetaDataUri()
            hasCMD && hasCMDUri -> throw RequestValidationError.OneOfClientMedataOrUri.asException()
            else -> null
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
