package eu.europa.ec.euidw.openid4vp

import java.io.Serializable
import java.net.URI


sealed interface DispatchOutcome : Serializable {
    data class RedirectURI(val value: URI) : DispatchOutcome

    object VerifierResponse : DispatchOutcome {
        override fun toString(): String = "VerifierResponse"
    }

}

interface Dispatcher {
    suspend fun dispatch(response: AuthorizationResponse): DispatchOutcome
}


