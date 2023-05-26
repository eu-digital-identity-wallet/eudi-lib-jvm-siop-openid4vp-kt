package eu.europa.ec.euidw.openid4vp

import java.io.Serializable
import java.net.URI

/**
 * The outcome of dispatching an [AuthorizationResponse] to
 * verifier/RP.
 */
sealed interface DispatchOutcome : Serializable {

    /**
     * The outcome of dispatching a [AuthorizationResponse.RedirectResponse]
     * Actually, in this case there are no side effects, just
     * the [redirect URI][value]
     */
    data class RedirectURI(val value: URI) : DispatchOutcome

    /**
     * The verifier/RP 's response to a [direct post][AuthorizationResponse.RedirectResponse]
     */
    sealed interface VerifierResponse : DispatchOutcome {
        /**
         * When verifier/RP acknowledged the direct post
         */
        data class Accepted(val redirectURI: URI?) : VerifierResponse

        /**
         * When verifier/RP reject the direct post
         */
        object Rejected : VerifierResponse {
            override fun toString(): String = "Rejected"
        }
    }
}

/**
 * Depending on the kind of [AuthorizationResponse], the interface
 * either dispatches the authorization response to the verifier/ RP
 * in the case of [director post][AuthorizationResponse.DirectPostResponse],
 * or produces an appropriate [redirect_uri][DispatchOutcome.RedirectURI],
 * in the case of [redirect][AuthorizationResponse.RedirectResponse]
 */
fun interface Dispatcher {

    /**
     * Method dispatches the given [response] to the verifier / RP.
     * In case of a [director post][AuthorizationResponse.DirectPostResponse] method performs the HTTP Post to
     * the verifier end-point (response_uri).
     * In case of a [redirect][AuthorizationResponse.RedirectResponse] method prepares an appropriate redirect_uri
     *
     * @param response the response to be dispatched to the verifier / RP
     * @return in case of [director post][AuthorizationResponse.DirectPostResponse] method returns
     * the [verifier's response][DispatchOutcome.VerifierResponse].
     * In the case of a [redirect][AuthorizationResponse.RedirectResponse]
     * method returns an appropriate [redirect_uri][DispatchOutcome.RedirectURI]
     */
    suspend fun dispatch(response: AuthorizationResponse): DispatchOutcome
}
