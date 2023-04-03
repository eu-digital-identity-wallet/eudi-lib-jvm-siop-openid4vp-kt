package niscy.eudiw.openid4vp

import eu.europa.ec.euidw.prex.JsonString
import eu.europa.ec.euidw.prex.PresentationExchange

sealed interface AuthorizationRequestValidationError {

    data class UnsupportedResponseType(val value: String) : AuthorizationRequestValidationError
    object MissingResponseType: AuthorizationRequestValidationError
    object MissingPresentationDefinition : AuthorizationRequestValidationError
    object NonHttpsPresentationDefinitionUri : AuthorizationRequestValidationError

}

internal fun <T> AuthorizationRequestValidationError.asFailure(): Result<T> =
    Result.failure(AuthorizationRequestValidationException(this))


class AuthorizationRequestValidationException(val error: AuthorizationRequestValidationError) : RuntimeException()



internal class AuthorizationRequestValidator(private val presentationExchange: PresentationExchange) {

    fun validate(authorizationRequest: AuthorizationRequestData): Result<ValidatedAuthorizationRequestData> = runCatching {

        ValidatedAuthorizationRequestData(
            responseType = responseType(authorizationRequest).getOrThrow(),
            presentationDefinitionSource = presentationDefinitionSource(authorizationRequest).getOrThrow(),
            clientIdScheme = clientIdScheme(authorizationRequest).getOrThrow(),
            clientMetaDataSource = clientMetaDataSource(authorizationRequest).getOrThrow(),
            nonce = TODO(),
            responseMode = TODO(),
            scope = TODO()
        )
    }

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
                PresentationExchange.jsonParser.decodePresentationDefinition(
                    JsonString(ar.presentationDefinition)
                ).map { PresentationDefinitionSource.PassByValue(it) }

            ar.presentationDefinition.isNullOrEmpty() && !ar.presentationDefinitionUri.isNullOrEmpty() ->
                HttpsUrl.make(ar.presentationDefinitionUri!!).fold(
                    onSuccess = { PresentationDefinitionSource.FetchByReference(it).success() },
                    onFailure = { AuthorizationRequestValidationError.NonHttpsPresentationDefinitionUri.asFailure() }
                )

            ar.scope != null -> TODO()
            else -> AuthorizationRequestValidationError.MissingPresentationDefinition.asFailure()
        }
    }

    private fun clientIdScheme(ar: AuthorizationRequestData): Result<ClientIdScheme> = TODO()

    private fun clientMetaDataSource(ar: AuthorizationRequestData): Result<ClientMetaDataSource> = TODO()


}





