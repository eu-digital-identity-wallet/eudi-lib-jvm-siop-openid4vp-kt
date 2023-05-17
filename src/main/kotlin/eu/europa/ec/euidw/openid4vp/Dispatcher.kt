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

fun interface Dispatcher {
    suspend fun dispatch(response: AuthorizationResponse): DispatchOutcome

}


