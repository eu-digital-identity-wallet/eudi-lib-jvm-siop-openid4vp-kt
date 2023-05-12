package eu.europa.ec.euidw.openid4vp.internal.dispatch

import eu.europa.ec.euidw.openid4vp.AuthorizationResponse
import eu.europa.ec.euidw.openid4vp.AuthorizationResponseDispatcher
import java.net.URL

object RedirectResponseDispatcher : AuthorizationResponseDispatcher<AuthorizationResponse.RedirectResponse, URL> {
    override suspend fun dispatch(response: AuthorizationResponse.RedirectResponse): URL {
        TODO("Not yet implemented")
    }

}