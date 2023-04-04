package eu.europa.ec.euidw.openid4vp

import eu.europa.ec.euidw.prex.JsonParser
import eu.europa.ec.euidw.prex.JsonString
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.jsonObject
import java.net.URLDecoder

sealed interface AuthorizationRequestValidationError {
    data class UnsupportedResponseType(val value: String) : AuthorizationRequestValidationError
    data class UnsupportedResponseMode(val value: String?) : AuthorizationRequestValidationError
    object MissingResponseType : AuthorizationRequestValidationError
    object MissingPresentationDefinition : AuthorizationRequestValidationError
    object NonHttpsPresentationDefinitionUri : AuthorizationRequestValidationError
    object NonHttpsRedirectUri : AuthorizationRequestValidationError
    object MissingRedirectUri : AuthorizationRequestValidationError
    object MissingResponseUri : AuthorizationRequestValidationError
    object NonHttpsResponseUri : AuthorizationRequestValidationError
    object ResponseUriMustNotBeProvided : AuthorizationRequestValidationError
    object RedirectUriMustNotBeProvided : AuthorizationRequestValidationError
    object MissingNonce : AuthorizationRequestValidationError
    object MissingClientId: AuthorizationRequestValidationError
    data class InvalidClientIdScheme(val value: String) : AuthorizationRequestValidationError
    object DirectPostMissingOrInvalidResponseUri : AuthorizationRequestValidationError

}

internal fun <T> AuthorizationRequestValidationError.asFailure(): Result<T> =
    Result.failure(AuthorizationRequestValidationException(this))


class AuthorizationRequestValidationException(val error: AuthorizationRequestValidationError) : RuntimeException()


internal class AuthorizationRequestValidator(private val presentationExchangeParser: JsonParser) {

    fun validate(authorizationRequest: OpenID4VPRequestData): Result<ValidatedOpenID4VPRequestData> = runCatching {
        val nonce = requiredNonce(authorizationRequest).getOrThrow()
        val responseType = authorizationRequest.requiredResponseType().getOrThrow()
        val responseMode = requiredResponseMode(authorizationRequest).getOrThrow()
        val clientIdScheme = authorizationRequest.parseClientIdScheme().getOrThrow()
        val clientId = authorizationRequest.requiredClientId().getOrThrow()
        val presentationDefinitionSource = parsePresentationDefinitionSource(authorizationRequest).getOrThrow()

        ValidatedOpenID4VPRequestData(
            responseType = responseType,
            presentationDefinitionSource = presentationDefinitionSource,
            clientIdScheme = clientIdScheme,
            clientMetaDataSource = optionalClientMetaDataSource(authorizationRequest).getOrThrow(),
            nonce = nonce,
            responseMode = responseMode,
            scope = authorizationRequest.scope,
            state = authorizationRequest.state,
            clientId = clientId
        )
    }



    private fun requiredResponseMode(openID4VPRequestData: OpenID4VPRequestData): Result<ResponseMode> {
        fun requiredRedirectUriAndNotProvidedResponseUri(): Result<HttpsUrl> {
            if (openID4VPRequestData.responseUri != null) AuthorizationRequestValidationError.ResponseUriMustNotBeProvided.asFailure<HttpsUrl>()
            return openID4VPRequestData.redirectUri?.let { HttpsUrl.make(it) }
                ?: AuthorizationRequestValidationError.MissingRedirectUri.asFailure()
        }

        fun requiredResponseUriAndNotProvidedRedirectUri(): Result<HttpsUrl> {
            if (openID4VPRequestData.redirectUri != null) AuthorizationRequestValidationError.RedirectUriMustNotBeProvided.asFailure<HttpsUrl>()
            return openID4VPRequestData.responseUri?.let { HttpsUrl.make(it) }
                ?: AuthorizationRequestValidationError.MissingResponseUri.asFailure()
        }

        return when (openID4VPRequestData.responseMode) {
            "direct_post" -> requiredResponseUriAndNotProvidedRedirectUri().map { ResponseMode.DirectPost(it) }
            "query" -> requiredRedirectUriAndNotProvidedResponseUri().map { ResponseMode.Query(it) }
            "fragment" -> requiredRedirectUriAndNotProvidedResponseUri().map { ResponseMode.Fragment(it) }
            else -> requiredRedirectUriAndNotProvidedResponseUri().map { ResponseMode.Fragment(it) }
        }


    }



    private fun requiredNonce(openID4VPRequestData: OpenID4VPRequestData): Result<String> =
        openID4VPRequestData.nonce?.success() ?: AuthorizationRequestValidationError.MissingNonce.asFailure()


    private fun OpenID4VPRequestData.requiredResponseType(): Result<ResponseType> {
        return when (responseType?.trim()) {
            null -> AuthorizationRequestValidationError.MissingResponseType.asFailure()
            "vp_token" -> ResponseType.VpToken.success()
            "vp_token id_token" -> ResponseType.VpAndIdToken.success()
            "id_token" -> ResponseType.IdToken.success()
            else -> AuthorizationRequestValidationError.UnsupportedResponseType(responseType).asFailure()
        }
    }


    private fun parsePresentationDefinitionSource(openID4VPRequestData: OpenID4VPRequestData): Result<PresentationDefinitionSource> {

        return when {
            !openID4VPRequestData.presentationDefinition.isNullOrEmpty() && openID4VPRequestData.presentationDefinitionUri.isNullOrEmpty() ->
                presentationExchangeParser.decodePresentationDefinition(
                    JsonString(openID4VPRequestData.presentationDefinition)
                ).map { PresentationDefinitionSource.PassByValue(it) }

            openID4VPRequestData.presentationDefinition.isNullOrEmpty() && !openID4VPRequestData.presentationDefinitionUri.isNullOrEmpty() ->
                HttpsUrl.make(openID4VPRequestData.presentationDefinitionUri).fold(
                    onSuccess = { PresentationDefinitionSource.FetchByReference(it).success() },
                    onFailure = { AuthorizationRequestValidationError.NonHttpsPresentationDefinitionUri.asFailure() }
                )

            openID4VPRequestData.scope != null -> TODO()
            else -> AuthorizationRequestValidationError.MissingPresentationDefinition.asFailure()
        }
    }

    private fun OpenID4VPRequestData.parseClientIdScheme(): Result<ClientIdScheme?> =
        if (clientIdScheme.isNullOrEmpty()) Result.success(null)
        else ClientIdScheme.make(clientIdScheme)?.success()
            ?: AuthorizationRequestValidationError.InvalidClientIdScheme(clientIdScheme).asFailure()

    private fun OpenID4VPRequestData.requiredClientId(): Result<String> =
        clientId?.success() ?: AuthorizationRequestValidationError.MissingClientId.asFailure()

    private fun optionalClientMetaDataSource(ar: OpenID4VPRequestData): Result<ClientMetaDataSource?> = runCatching {

        when {
            !ar.clientMetaData.isNullOrEmpty() && ar.clientMetadataUri.isNullOrEmpty() -> {
                val decoded = URLDecoder.decode(ar.clientMetaData, "UTF-8")
                val j = Json.parseToJsonElement(decoded).jsonObject
                return ClientMetaDataSource.PassByValue(j).success()
            }

            else -> TODO()
        }

    }

}







