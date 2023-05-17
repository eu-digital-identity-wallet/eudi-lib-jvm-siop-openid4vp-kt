package eu.europa.ec.euidw.openid4vp.internal.ktor

import eu.europa.ec.euidw.openid4vp.AuthorizationResponse.DirectPostResponse
import eu.europa.ec.euidw.openid4vp.DispatchOutcome
import eu.europa.ec.euidw.openid4vp.HttpFormPost
import eu.europa.ec.euidw.openid4vp.asURI
import eu.europa.ec.euidw.openid4vp.internal.dispatch.AuthorizationResponseDispatcher
import eu.europa.ec.euidw.openid4vp.internal.dispatch.ManagedAuthorizationResponseDispatcher
import io.ktor.client.*
import kotlinx.serialization.json.jsonPrimitive

internal class KtorDirectPostResponseDispatcher<in A : DirectPostResponse>(
    httpClientFactory: () -> HttpClient,
    proxyFactory: (HttpFormPost<DispatchOutcome.VerifierResponse>) -> AuthorizationResponseDispatcher<A, DispatchOutcome.VerifierResponse>
) : ManagedAuthorizationResponseDispatcher<A> {

    /**
     * The ktor http client
     */
    private val httpClient: HttpClient by lazy(httpClientFactory)

    /**
     * The actual or proxied [AuthorizationResponseDispatcher]
     */
    private val proxy: AuthorizationResponseDispatcher<A, DispatchOutcome.VerifierResponse> by lazy {
        proxyFactory(HttpKtorAdapter.httpFormPost(httpClient))
    }

    override suspend fun dispatch(response: A) = proxy.dispatch(response)

    override fun close() = httpClient.close()


}


