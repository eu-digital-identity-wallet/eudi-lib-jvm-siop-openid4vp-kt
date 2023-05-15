package eu.europa.ec.euidw.openid4vp.internal.dispatch

import eu.europa.ec.euidw.openid4vp.AuthorizationResponse
import java.io.Closeable

internal interface AuthorizationResponseDispatcher<in A : AuthorizationResponse, out T> {
    suspend fun dispatch(response: A): T
}

internal interface ManagedAuthorizationResponseDispatcher<in A : AuthorizationResponse.DirectPostResponse> :
    AuthorizationResponseDispatcher<A, Unit>, Closeable