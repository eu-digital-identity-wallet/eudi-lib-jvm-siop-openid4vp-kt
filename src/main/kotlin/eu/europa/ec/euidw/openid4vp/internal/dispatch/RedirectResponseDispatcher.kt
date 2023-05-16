package eu.europa.ec.euidw.openid4vp.internal.dispatch

import eu.europa.ec.euidw.openid4vp.AuthorizationResponse
import eu.europa.ec.euidw.openid4vp.AuthorizationResponse.RedirectResponse
import java.net.URI

object RedirectResponseDispatcher : AuthorizationResponseDispatcher<RedirectResponse, URI> {
    override suspend fun dispatch(response: RedirectResponse): URI = when (response) {
        is AuthorizationResponse.Fragment -> TODO()
        is AuthorizationResponse.FragmentJwt -> TODO()
        is AuthorizationResponse.Query -> TODO()
        is AuthorizationResponse.QueryJwt -> TODO()
    }
}