package eu.europa.ec.eudi.openid4vp.internal.response

import eu.europa.ec.eudi.openid4vp.AuthorizationRequestError
import eu.europa.ec.eudi.openid4vp.EncryptionParameters
import eu.europa.ec.eudi.openid4vp.ErrorDispatchDetails
import eu.europa.ec.eudi.openid4vp.ResponseMode

internal fun AuthorizationRequestError.responseWith(
    di: ErrorDispatchDetails,
    encryptionParameters: EncryptionParameters?,
): AuthorizationResponse {
    val payload = AuthorizationResponsePayload.InvalidRequest(
        error = this,
        state = di.state,
        nonce = di.nonce,
        encryptionParameters = encryptionParameters
    )
    return responseWith(di, payload)
}

private fun responseWith(
    di: ErrorDispatchDetails,
    data: AuthorizationResponsePayload.InvalidRequest,
): AuthorizationResponse {
    fun jarmOption() = checkNotNull(di.jarmRequirement)

    return when (val mode = di.responseMode) {
        is ResponseMode.DirectPost -> AuthorizationResponse.DirectPost(mode.responseURI, data)
        is ResponseMode.DirectPostJwt -> AuthorizationResponse.DirectPostJwt(mode.responseURI, data, jarmOption())
        is ResponseMode.Fragment -> AuthorizationResponse.Fragment(mode.redirectUri, data)
        is ResponseMode.FragmentJwt -> AuthorizationResponse.FragmentJwt(mode.redirectUri, data, jarmOption())
        is ResponseMode.Query -> AuthorizationResponse.Query(mode.redirectUri, data)
        is ResponseMode.QueryJwt -> AuthorizationResponse.QueryJwt(mode.redirectUri, data, jarmOption())
    }
}
