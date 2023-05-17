package eu.europa.ec.euidw.openid4vp

import java.io.Serializable
import java.net.URI


sealed interface DispatchOutcome : Serializable {
    data class RedirectURI(val value: URI) : DispatchOutcome

    sealed interface VerifierResponse : DispatchOutcome {
        data class Accepted(val redirectURI: URI?) : VerifierResponse
        object Rejected : VerifierResponse {
            override fun toString(): String = "Rejected"
        }
    }

}

interface Dispatcher {
    suspend fun dispatch(response: AuthorizationResponse): DispatchOutcome
}


