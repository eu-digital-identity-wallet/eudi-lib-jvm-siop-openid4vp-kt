package eu.europa.ec.euidw.openid4vp

import eu.europa.ec.euidw.prex.JsonParser
import eu.europa.ec.euidw.prex.JsonString
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import java.net.URLDecoder

sealed interface AuthorizationRequestValidationError {

    data class UnsupportedResponseType(val value: String) : AuthorizationRequestValidationError
    object MissingResponseType : AuthorizationRequestValidationError
    object MissingPresentationDefinition : AuthorizationRequestValidationError
    object NonHttpsPresentationDefinitionUri : AuthorizationRequestValidationError

    object MissingNonce : AuthorizationRequestValidationError
    data class InvalidClientIdScheme(val value: String) : AuthorizationRequestValidationError

}

internal fun <T> AuthorizationRequestValidationError.asFailure(): Result<T> =
    Result.failure(AuthorizationRequestValidationException(this))


class AuthorizationRequestValidationException(val error: AuthorizationRequestValidationError) : RuntimeException()


internal class AuthorizationRequestValidator(private val presentationExchangeParser: JsonParser) {

    fun validate(authorizationRequest: AuthorizationRequestData): Result<ValidatedAuthorizationRequestData> =
        runCatching {
            ValidatedAuthorizationRequestData(
                responseType = responseType(authorizationRequest).getOrThrow(),
                presentationDefinitionSource = presentationDefinitionSource(authorizationRequest).getOrThrow(),
                clientIdScheme = clientIdScheme(authorizationRequest).getOrThrow(),
                clientMetaDataSource = clientMetaDataSource(authorizationRequest).getOrThrow(),
                nonce = nonce(authorizationRequest).getOrThrow(),
                responseMode = ResponseMode.Fragment,
                scope = null,
                state = authorizationRequest.state
            )
        }

    private fun nonce(ar: AuthorizationRequestData): Result<Nonce> =
        if (ar.nonce != null) ar.nonce.success()
        else AuthorizationRequestValidationError.MissingNonce.asFailure()


    private fun responseType(ar: AuthorizationRequestData): Result<ResponseType> {
        return when (ar.responseType?.trim()) {
            null -> AuthorizationRequestValidationError.MissingResponseType.asFailure()
            "vp_token" -> ResponseType.VpToken.success()
            "vp_token id_token" -> ResponseType.VpAndIdToken.success()
            "id_token" -> ResponseType.IdToken.success()
            else -> AuthorizationRequestValidationError.UnsupportedResponseType(ar.responseType).asFailure()
        }
    }

    private fun presentationDefinitionSource(ar: AuthorizationRequestData): Result<PresentationDefinitionSource> {

        return when {
            !ar.presentationDefinition.isNullOrEmpty() && ar.presentationDefinitionUri.isNullOrEmpty() ->
                presentationExchangeParser.decodePresentationDefinition(
                    JsonString(ar.presentationDefinition)
                ).map { PresentationDefinitionSource.PassByValue(it) }

            ar.presentationDefinition.isNullOrEmpty() && !ar.presentationDefinitionUri.isNullOrEmpty() ->
                HttpsUrl.make(ar.presentationDefinitionUri).fold(
                    onSuccess = { PresentationDefinitionSource.FetchByReference(it).success() },
                    onFailure = { AuthorizationRequestValidationError.NonHttpsPresentationDefinitionUri.asFailure() }
                )

            ar.scope != null -> TODO()
            else -> AuthorizationRequestValidationError.MissingPresentationDefinition.asFailure()
        }
    }

    private fun clientIdScheme(ar: AuthorizationRequestData): Result<ClientIdScheme?> =
        if (ar.clientIdScheme.isNullOrEmpty()) Result.success(null)
        else ClientIdScheme.make(ar.clientIdScheme)?.success() ?: AuthorizationRequestValidationError.InvalidClientIdScheme(ar.clientIdScheme).asFailure()



    private fun clientMetaDataSource(ar: AuthorizationRequestData): Result<ClientMetaDataSource?> = runCatching {

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





