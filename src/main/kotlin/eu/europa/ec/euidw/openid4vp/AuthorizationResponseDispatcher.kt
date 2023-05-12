package eu.europa.ec.euidw.openid4vp

import eu.europa.ec.euidw.openid4vp.AuthorizationResponse.*
import eu.europa.ec.euidw.openid4vp.internal.dispatch.DirectPostDispatcher
import eu.europa.ec.euidw.openid4vp.internal.dispatch.DirectPostJwtDispatcher
import eu.europa.ec.euidw.openid4vp.internal.dispatch.RedirectResponseDispatcher
import eu.europa.ec.euidw.openid4vp.internal.ktor.KtorDirectPostResponseDispatcher
import java.io.Closeable
import java.net.URL

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
