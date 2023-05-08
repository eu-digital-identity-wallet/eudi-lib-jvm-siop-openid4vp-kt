package eu.europa.ec.euidw.openid4vp

sealed interface RequestValidationError {

    //
    // Response Type errors
    //
    data class UnsupportedResponseType(val value: String) : RequestValidationError
    object MissingResponseType : RequestValidationError

    //
    // Response Mode errors
    //
    data class UnsupportedResponseMode(val value: String?) : RequestValidationError

    //
    // Presentation Definition errors
    //
    object MissingPresentationDefinition : RequestValidationError
    data class InvalidPresentationDefinition(val cause: Throwable): RequestValidationError
    object InvalidPresentationDefinitionUri : RequestValidationError
    object InvalidRedirectUri : RequestValidationError
    object MissingRedirectUri : RequestValidationError
    object MissingResponseUri : RequestValidationError
    object InvalidResponseUri : RequestValidationError
    object ResponseUriMustNotBeProvided : RequestValidationError
    object RedirectUriMustNotBeProvided : RequestValidationError
    object MissingState : RequestValidationError
    object MissingNonce : RequestValidationError
    object MissingScope : RequestValidationError
    object MissingClientId : RequestValidationError

    object InvalidClientMetaDataUri : RequestValidationError
    object OneOfClientMedataOrUri : RequestValidationError
    data class InvalidClientIdScheme(val value: String) : RequestValidationError

}



sealed interface ResolutionError {
    data class PresentationDefinitionNotFoundForScope(val scope: Scope) : ResolutionError
    object FetchingPresentationDefinitionNotSupported : ResolutionError
    data class UnableToFetchPresentationDefinition(val cause: Throwable) : ResolutionError
    data class UnableToFetchClientMetadata(val cause: Throwable) : ResolutionError
    data class UnableToFetchRequestObject(val cause: Throwable) : ResolutionError
}




data class ResolutionException(val error: ResolutionError) : RuntimeException()



internal fun RequestValidationError.asException(): AuthorizationRequestValidationException =
    AuthorizationRequestValidationException(this)

internal fun <T> RequestValidationError.asFailure(): Result<T> =
    Result.failure(asException())


data class AuthorizationRequestValidationException(val error: RequestValidationError) : RuntimeException()








