package eu.europa.ec.euidw.openid4vp

import eu.europa.ec.euidw.openid4vp.AuthorizationRequestValidationError.*
import eu.europa.ec.euidw.prex.JsonParser
import eu.europa.ec.euidw.prex.JsonString
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.jsonObject
import java.net.URLDecoder

sealed interface AuthorizationRequestValidationError {

    //
    // Response Type errors
    //
    data class UnsupportedResponseType(val value: String) : AuthorizationRequestValidationError
    object MissingResponseType : AuthorizationRequestValidationError

    //
    // Response Mode errors
    //
    data class UnsupportedResponseMode(val value: String?) : AuthorizationRequestValidationError

    //
    // Presentation Definition errors
    //
    object MissingPresentationDefinition : AuthorizationRequestValidationError
    data class InvalidPresentationDefinition(val cause: Throwable): AuthorizationRequestValidationError
    object InvalidPresentationDefinitionUri : AuthorizationRequestValidationError
    object InvalidRedirectUri : AuthorizationRequestValidationError
    object MissingRedirectUri : AuthorizationRequestValidationError
    object MissingResponseUri : AuthorizationRequestValidationError
    object InvalidResponseUri : AuthorizationRequestValidationError
    object ResponseUriMustNotBeProvided : AuthorizationRequestValidationError
    object RedirectUriMustNotBeProvided : AuthorizationRequestValidationError
    object MissingNonce : AuthorizationRequestValidationError
    object MissingClientId : AuthorizationRequestValidationError

    object InvalidClientMetaDataUri : AuthorizationRequestValidationError
    object OneOfClientMedataOrUri : AuthorizationRequestValidationError
    data class InvalidClientIdScheme(val value: String) : AuthorizationRequestValidationError

}

internal fun AuthorizationRequestValidationError.asException(): AuthorizationRequestValidationException =
    AuthorizationRequestValidationException(this)

internal fun <T> AuthorizationRequestValidationError.asFailure(): Result<T> =
    Result.failure(asException())


data class AuthorizationRequestValidationException(val error: AuthorizationRequestValidationError) : RuntimeException()


internal class AuthorizationRequestValidator(private val presentationExchangeParser: JsonParser) {

    fun validate(authorizationRequest: OpenID4VPRequestData): Result<ValidatedOpenID4VPRequestData> = runCatching {
        val scope = authorizationRequest.scope?.let { Scope.make(it) }
        val nonce = requiredNonce(authorizationRequest).getOrThrow()
        val responseType = requiredResponseType(authorizationRequest).getOrThrow()
        val responseMode = requiredResponseMode(authorizationRequest).getOrThrow()
        val clientIdScheme = optionalClientIdScheme(authorizationRequest).getOrThrow()
        val clientId = requiredClientId(authorizationRequest).getOrThrow()
        val presentationDefinitionSource = parsePresentationDefinitionSource(authorizationRequest, scope).getOrThrow()
        val clientMetaDataSource = optionalClientMetaDataSource(authorizationRequest).getOrThrow()

        ValidatedOpenID4VPRequestData(
            responseType = responseType,
            presentationDefinitionSource = presentationDefinitionSource,
            clientIdScheme = clientIdScheme,
            clientMetaDataSource = clientMetaDataSource,
            nonce = nonce,
            responseMode = responseMode,
            scope = scope,
            state = authorizationRequest.state,
            clientId = clientId
        )
    }


    private fun requiredResponseMode(unvalidated: OpenID4VPRequestData): Result<ResponseMode> {

        fun requiredRedirectUriAndNotProvidedResponseUri(): Result<HttpsUrl> =
            if (unvalidated.responseUri != null) ResponseUriMustNotBeProvided.asFailure()
            else when (val uri = unvalidated.redirectUri) {
                null -> MissingRedirectUri.asFailure()
                else -> HttpsUrl.make(uri).mapError { InvalidRedirectUri.asException() }
            }

        fun requiredResponseUriAndNotProvidedRedirectUri(): Result<HttpsUrl> =
            if (unvalidated.redirectUri != null) RedirectUriMustNotBeProvided.asFailure()
            else when (val uri = unvalidated.responseUri) {
                null -> MissingResponseUri.asFailure()
                else -> HttpsUrl.make(uri).mapError { InvalidResponseUri.asException() }
            }

        return when (unvalidated.responseMode) {
            "direct_post" -> requiredResponseUriAndNotProvidedRedirectUri().map { ResponseMode.DirectPost(it) }
            "query" -> requiredRedirectUriAndNotProvidedResponseUri().map { ResponseMode.Query(it) }
            "fragment" -> requiredRedirectUriAndNotProvidedResponseUri().map { ResponseMode.Fragment(it) }
            null -> requiredRedirectUriAndNotProvidedResponseUri().map { ResponseMode.Fragment(it) }
            else -> UnsupportedResponseMode(unvalidated.responseMode).asFailure()
        }
    }


    private fun requiredNonce(unvalidated: OpenID4VPRequestData): Result<String> =
        unvalidated.nonce?.success() ?: MissingNonce.asFailure()


    private fun requiredResponseType(unvalidated: OpenID4VPRequestData): Result<ResponseType> =
        when (val rt = unvalidated.responseType?.trim()) {
            "vp_token" -> ResponseType.VpToken.success()
            "vp_token id_token" -> ResponseType.VpAndIdToken.success()
            "id_token" -> ResponseType.IdToken.success()
            null -> MissingResponseType.asFailure()
            else -> UnsupportedResponseType(rt).asFailure()
        }


    private fun parsePresentationDefinitionSource(unvalidated: OpenID4VPRequestData, scope: Scope?): Result<PresentationDefinitionSource> {
        val hasPd = !unvalidated.presentationDefinition.isNullOrEmpty()
        val hasPdUri = !unvalidated.presentationDefinitionUri.isNullOrEmpty()
        val hasScope = null != scope

        fun requiredPd() = runCatching {
            val pd = presentationExchangeParser.decodePresentationDefinition(
                JsonString(unvalidated.presentationDefinition!!)
            ).mapError { InvalidPresentationDefinition(it).asException() }.getOrThrow()
            PresentationDefinitionSource.PassByValue(pd)
        }


        fun requiredPdUri() = runCatching {
            val pdUri = HttpsUrl.make(unvalidated.presentationDefinitionUri!!).getOrThrow()
            PresentationDefinitionSource.FetchByReference(pdUri)
        }.mapError { InvalidPresentationDefinitionUri.asException() }

        fun requiredScope() = PresentationDefinitionSource.Implied(scope!!).success()

        return when {
            hasPd && !hasPdUri -> requiredPd()
            !hasPd && hasPdUri -> requiredPdUri()
            hasScope -> requiredScope()
            else -> MissingPresentationDefinition.asFailure()
        }
    }

    private fun optionalClientIdScheme(unvalidated: OpenID4VPRequestData): Result<ClientIdScheme?> =
        if (unvalidated.clientIdScheme.isNullOrEmpty()) Result.success(null)
        else ClientIdScheme.make(unvalidated.clientIdScheme)?.success()
            ?: InvalidClientIdScheme(unvalidated.clientIdScheme).asFailure()

    private fun requiredClientId(unvalidated: OpenID4VPRequestData): Result<String> =
        unvalidated.clientId?.success() ?: MissingClientId.asFailure()

    private fun optionalClientMetaDataSource(unvalidated: OpenID4VPRequestData): Result<ClientMetaDataSource?> {

        val hasCMD = !unvalidated.clientMetaData.isNullOrEmpty()
        val hasCMDUri = !unvalidated.clientMetadataUri.isNullOrEmpty()

        fun requiredClientMetaData() = runCatching {
            val decoded = URLDecoder.decode(unvalidated.clientMetaData, "UTF-8")
            val j = Json.parseToJsonElement(decoded).jsonObject
            ClientMetaDataSource.PassByValue(j)
        }
        fun requiredClientMetaDataUri() = runCatching {
            val uri = HttpsUrl.make(unvalidated.clientMetadataUri!!)
                .mapError { InvalidClientMetaDataUri.asException() }
                .getOrThrow()
            ClientMetaDataSource.FetchByReference(uri)
        }

        return when {
            hasCMD && !hasCMDUri -> requiredClientMetaData()
            !hasCMD && hasCMDUri -> requiredClientMetaDataUri()
            hasCMD && hasCMDUri -> OneOfClientMedataOrUri.asFailure()
            else -> Result.success(null)
        }

    }

}







