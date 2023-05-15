package eu.europa.ec.euidw.openid4vp

import eu.europa.ec.euidw.openid4vp.AuthorizationResponse.*
import eu.europa.ec.euidw.openid4vp.internal.dispatch.DirectPostDispatcher
import eu.europa.ec.euidw.openid4vp.internal.dispatch.DirectPostJwtDispatcher
import eu.europa.ec.euidw.openid4vp.internal.dispatch.RedirectResponseDispatcher
import eu.europa.ec.euidw.openid4vp.internal.ktor.KtorDirectPostResponseDispatcher
import java.io.Closeable
import java.io.Serializable
import java.net.URL


sealed interface DispatchOutcome : Serializable {

    data class RedirectUrl(val value: URL) : DispatchOutcome
    object DirectPostResponse : DispatchOutcome {
        override fun toString(): String = "DirectPostResponse"
    }

}

interface Dispatcher {
    suspend fun dispatch(response: AuthorizationResponse): DispatchOutcome

    companion object {
        val Default: Dispatcher = object : Dispatcher {
            override suspend fun dispatch(response: AuthorizationResponse): DispatchOutcome {
                return when (response) {
                    is DirectPost -> ManagedAuthorizationResponseDispatcher.directPost().use { dispatcher ->
                        dispatcher.dispatch(response).run {
                            DispatchOutcome.DirectPostResponse
                        }
                    }

                    is DirectPostJwt -> ManagedAuthorizationResponseDispatcher.directPostJwt().use { dispatcher ->
                        dispatcher.dispatch(response).run {
                            DispatchOutcome.DirectPostResponse
                        }
                    }

                    is RedirectResponse -> AuthorizationResponseDispatcher.Redirect.dispatch(response)
                        .run { DispatchOutcome.RedirectUrl(this) }
                }
            }

        }
    }
}

interface AuthorizationResponseDispatcher<in A : AuthorizationResponse, out T> {
    suspend fun dispatch(response: A): T

    companion object {
        val Redirect: AuthorizationResponseDispatcher<RedirectResponse, URL> = RedirectResponseDispatcher
    }
}

interface ManagedAuthorizationResponseDispatcher<in A : DirectPostResponse> :
    AuthorizationResponseDispatcher<A, Unit>, Closeable {
    companion object {

        fun directPost(): ManagedAuthorizationResponseDispatcher<DirectPost> =
            KtorDirectPostResponseDispatcher { DirectPostDispatcher(it) }

        fun directPostJwt(): ManagedAuthorizationResponseDispatcher<DirectPostJwt> =
            KtorDirectPostResponseDispatcher { DirectPostJwtDispatcher(it) }
    }
}
