package eu.europa.ec.euidw.openid4vp

sealed interface SiopId4VPRequestValidationError {

    //
    // Response Type errors
    //
    data class UnsupportedResponseType(val value: String) : SiopId4VPRequestValidationError
    object MissingResponseType : SiopId4VPRequestValidationError

    //
    // Response Mode errors
    //
    data class UnsupportedResponseMode(val value: String?) : SiopId4VPRequestValidationError

    //
    // Presentation Definition errors
    //
    object MissingPresentationDefinition : SiopId4VPRequestValidationError
    data class InvalidPresentationDefinition(val cause: Throwable): SiopId4VPRequestValidationError
    object InvalidPresentationDefinitionUri : SiopId4VPRequestValidationError
    object InvalidRedirectUri : SiopId4VPRequestValidationError
    object MissingRedirectUri : SiopId4VPRequestValidationError
    object MissingResponseUri : SiopId4VPRequestValidationError
    object InvalidResponseUri : SiopId4VPRequestValidationError
    object ResponseUriMustNotBeProvided : SiopId4VPRequestValidationError
    object RedirectUriMustNotBeProvided : SiopId4VPRequestValidationError
    object MissingState : SiopId4VPRequestValidationError
    object MissingNonce : SiopId4VPRequestValidationError
    object MissingScope : SiopId4VPRequestValidationError
    object MissingClientId : SiopId4VPRequestValidationError

    object InvalidClientMetaDataUri : SiopId4VPRequestValidationError
    object OneOfClientMedataOrUri : SiopId4VPRequestValidationError
    data class InvalidClientIdScheme(val value: String) : SiopId4VPRequestValidationError

}



sealed interface ResolutionError {
    data class PresentationDefinitionNotFoundForScope(val scope: Scope) : ResolutionError
    object FetchingPresentationDefinitionNotSupported : ResolutionError
    data class UnableToFetchPresentationDefinition(val cause: Throwable) : ResolutionError
    data class UnableToFetchClientMetadata(val cause: Throwable) : ResolutionError
    data class UnableToFetchRequestObject(val cause: Throwable) : ResolutionError
}




data class ResolutionException(val error: ResolutionError) : RuntimeException()



internal fun SiopId4VPRequestValidationError.asException(): AuthorizationRequestValidationException =
    AuthorizationRequestValidationException(this)

internal fun <T> SiopId4VPRequestValidationError.asFailure(): Result<T> =
    Result.failure(asException())


data class AuthorizationRequestValidationException(val error: SiopId4VPRequestValidationError) : RuntimeException()








