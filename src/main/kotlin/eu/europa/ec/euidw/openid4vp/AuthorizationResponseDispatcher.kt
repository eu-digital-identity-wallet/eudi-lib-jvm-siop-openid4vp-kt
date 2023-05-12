package eu.europa.ec.euidw.openid4vp

import eu.europa.ec.euidw.openid4vp.internal.dispatch.DirectPostResponseDispatcher
import eu.europa.ec.euidw.openid4vp.internal.dispatch.RedirectResponseDispatcher
import eu.europa.ec.euidw.openid4vp.internal.ktor.KtorDirectPostResponseDispatcher
import java.io.Closeable
import java.net.URL

interface AuthorizationResponseDispatcher<in A : AuthorizationResponse, out T> {
    suspend fun dispatch(response : A) : T

    companion object {
        fun makeDirectPostsDispatcher(
            httpFormPost : HttpFormPost
        ) : AuthorizationResponseDispatcher<AuthorizationResponse.DirectPostResponse, Unit> {
            return DirectPostResponseDispatcher(httpFormPost)
        }

        fun makeRedirectsDispatcher() : AuthorizationResponseDispatcher<AuthorizationResponse.RedirectResponse, URL> {
            return RedirectResponseDispatcher
        }
    }
}

interface ManagedAuthorizationResponseDispatcher : AuthorizationResponseDispatcher<AuthorizationResponse.DirectPostResponse, Unit>, Closeable {
    companion object {
        /**
         * A factory method for obtaining an instance of [ManagedAuthorizationResponseDispatcher] which
         * uses the Ktor client for performing http calls
         */
        fun ktor(): ManagedAuthorizationResponseDispatcher {
            return KtorDirectPostResponseDispatcher()
        }
    }
}
