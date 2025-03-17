package eu.europa.ec.eudi.openid4vp

interface ErrorDispatcher {
    suspend fun dispatchError(
        error: AuthorizationRequestError,
        di: ErrorDispatchDetails,
        encryptionParameters: EncryptionParameters?,
    ): DispatchOutcome = when (di.responseMode) {
        is ResponseMode.DirectPost -> post(error, di, encryptionParameters)
        is ResponseMode.DirectPostJwt -> post(error, di, encryptionParameters)
        is ResponseMode.Query -> encodeRedirectURI(error, di, encryptionParameters)
        is ResponseMode.QueryJwt -> encodeRedirectURI(error, di, encryptionParameters)
        is ResponseMode.Fragment -> encodeRedirectURI(error, di, encryptionParameters)
        is ResponseMode.FragmentJwt -> encodeRedirectURI(error, di, encryptionParameters)
    }

    suspend fun post(
        error: AuthorizationRequestError,
        di: ErrorDispatchDetails,
        encryptionParameters: EncryptionParameters?,
    ): DispatchOutcome.VerifierResponse

    suspend fun encodeRedirectURI(
        error: AuthorizationRequestError,
        di: ErrorDispatchDetails,
        encryptionParameters: EncryptionParameters?,
    ): DispatchOutcome.RedirectURI
}