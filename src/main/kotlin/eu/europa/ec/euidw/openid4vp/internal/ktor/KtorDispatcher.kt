package eu.europa.ec.euidw.openid4vp.internal.ktor

import eu.europa.ec.euidw.openid4vp.AuthorizationResponse
import eu.europa.ec.euidw.openid4vp.DispatchOutcome
import eu.europa.ec.euidw.openid4vp.Dispatcher
import eu.europa.ec.euidw.openid4vp.internal.dispatch.DirectPostDispatcher
import eu.europa.ec.euidw.openid4vp.internal.dispatch.DirectPostJwtDispatcher
import eu.europa.ec.euidw.openid4vp.internal.dispatch.ManagedAuthorizationResponseDispatcher
import eu.europa.ec.euidw.openid4vp.internal.dispatch.RedirectResponseDispatcher
import io.ktor.client.*

internal class KtorDispatcher(private val httpClientFactory: ()->HttpClient) : Dispatcher {

    private fun directPost(): ManagedAuthorizationResponseDispatcher<AuthorizationResponse.DirectPost> =
        KtorDirectPostResponseDispatcher(httpClientFactory) { DirectPostDispatcher(it) }

    private fun directPostJwt(): ManagedAuthorizationResponseDispatcher<AuthorizationResponse.DirectPostJwt> =
        KtorDirectPostResponseDispatcher(httpClientFactory) { DirectPostJwtDispatcher(it) }

    override suspend fun dispatch(response: AuthorizationResponse): DispatchOutcome {
        return when (response) {
            is AuthorizationResponse.DirectPost -> directPost().use { dispatcher ->
                dispatcher.dispatch(response)
            }

            is AuthorizationResponse.DirectPostJwt -> directPostJwt().use { dispatcher ->
                dispatcher.dispatch(response)
            }

            is AuthorizationResponse.RedirectResponse -> {
                val uri = RedirectResponseDispatcher.dispatch(response)
                DispatchOutcome.RedirectURI(uri)
            }
        }
    }
}
