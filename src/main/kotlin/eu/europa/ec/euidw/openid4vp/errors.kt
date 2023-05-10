package eu.europa.ec.euidw.openid4vp

sealed interface AuthorizationRequestError
sealed interface RequestValidationError : AuthorizationRequestError{

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



sealed interface ResolutionError : AuthorizationRequestError{
    data class PresentationDefinitionNotFoundForScope(val scope: Scope) : ResolutionError
    object FetchingPresentationDefinitionNotSupported : ResolutionError
    data class UnableToFetchPresentationDefinition(val cause: Throwable) : ResolutionError
    data class UnableToFetchClientMetadata(val cause: Throwable) : ResolutionError
    data class UnableToFetchRequestObject(val cause: Throwable) : ResolutionError
}


fun AuthorizationRequestError.asException(): AuthorizationRequestException =
    AuthorizationRequestException(this)

fun <T> AuthorizationRequestError.asFailure(): Result<T> =
    Result.failure(asException())


data class AuthorizationRequestException(val error: AuthorizationRequestError) : RuntimeException()








