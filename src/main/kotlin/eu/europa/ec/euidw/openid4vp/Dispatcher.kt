package eu.europa.ec.euidw.openid4vp

import eu.europa.ec.euidw.openid4vp.AuthorizationResponse.*
import eu.europa.ec.euidw.openid4vp.internal.dispatch.DirectPostDispatcher
import eu.europa.ec.euidw.openid4vp.internal.dispatch.DirectPostJwtDispatcher
import eu.europa.ec.euidw.openid4vp.internal.dispatch.ManagedAuthorizationResponseDispatcher
import eu.europa.ec.euidw.openid4vp.internal.dispatch.RedirectResponseDispatcher
import eu.europa.ec.euidw.openid4vp.internal.ktor.KtorDirectPostResponseDispatcher
import java.io.Serializable
import java.net.URL


sealed interface DispatchOutcome : Serializable {

    data class RedirectUrl(val value: URL) : DispatchOutcome
    object VerifierResponse : DispatchOutcome {
        override fun toString(): String = "VerifierResponse"
    }

}

interface Dispatcher {
    suspend fun dispatch(response: AuthorizationResponse): DispatchOutcome

    companion object {

        val Default: Dispatcher = object : Dispatcher {

            private fun directPost(): ManagedAuthorizationResponseDispatcher<DirectPost> =
                KtorDirectPostResponseDispatcher { DirectPostDispatcher(it) }

            private fun directPostJwt(): ManagedAuthorizationResponseDispatcher<DirectPostJwt> =
                KtorDirectPostResponseDispatcher { DirectPostJwtDispatcher(it) }

            override suspend fun dispatch(response: AuthorizationResponse): DispatchOutcome {
                return when (response) {
                    is DirectPost -> directPost().use { dispatcher ->
                        dispatcher.dispatch(response)
                        DispatchOutcome.VerifierResponse
                    }

                    is DirectPostJwt -> directPostJwt().use { dispatcher ->
                        dispatcher.dispatch(response)
                        DispatchOutcome.VerifierResponse
                    }

                    is RedirectResponse -> {
                        val uri = RedirectResponseDispatcher.dispatch(response)
                        DispatchOutcome.RedirectUrl(uri)
                    }
                }
            }
        }


    }
}


