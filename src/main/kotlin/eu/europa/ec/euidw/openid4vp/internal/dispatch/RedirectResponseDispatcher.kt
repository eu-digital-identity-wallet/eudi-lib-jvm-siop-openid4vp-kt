package eu.europa.ec.euidw.openid4vp.internal.dispatch

import eu.europa.ec.euidw.openid4vp.AuthorizationResponse
import eu.europa.ec.euidw.openid4vp.AuthorizationResponse.RedirectResponse
import eu.europa.ec.euidw.openid4vp.AuthorizationResponseDispatcher
import java.net.URL

object RedirectResponseDispatcher : AuthorizationResponseDispatcher<RedirectResponse, URL> {
    override suspend fun dispatch(response: RedirectResponse): URL = when (response) {
        is AuthorizationResponse.Fragment -> TODO()
        is AuthorizationResponse.FragmentJwt -> TODO()
        is AuthorizationResponse.Query -> TODO()
        is AuthorizationResponse.QueryJwt -> TODO()
    }


}