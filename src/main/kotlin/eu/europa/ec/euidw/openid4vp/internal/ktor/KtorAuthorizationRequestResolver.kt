package eu.europa.ec.euidw.openid4vp.internal.ktor

import eu.europa.ec.euidw.openid4vp.AuthorizationRequest
import eu.europa.ec.euidw.openid4vp.AuthorizationRequestResolver
import eu.europa.ec.euidw.openid4vp.ManagedAuthorizationRequestResolver
import eu.europa.ec.euidw.openid4vp.WalletOpenId4VPConfig
import eu.europa.ec.euidw.openid4vp.internal.request.DefaultAuthorizationRequestResolver
import io.ktor.client.*
import io.ktor.client.request.*
import io.ktor.client.statement.*
import io.ktor.http.*

/**
 * An implementation of [AuthorizationRequestResolver] which uses Ktor client
 *
 * Class implements also the [java.lang.AutoCloseable] interface so make sure that after using
 * the instance to either call [KtorAuthorizationRequestResolver.close] or use it via
 * [use] method.
 *
 * To properly instantiate this class a proper HTTP engine needs to be made
 * available at runtime
 *
 * @see <a href="https://ktor.io/docs/client-dependencies.html#engine-dependency">Ktor Client</a>
 */
internal class KtorAuthorizationRequestResolver(
    walletOpenId4VPConfig: WalletOpenId4VPConfig
) : ManagedAuthorizationRequestResolver {

    /**
     * The ktor http client
     */
    private val httpClient: HttpClient by lazy { HttpKtorAdapter.createKtorClient() }

    /**
     * The actual or proxied [AuthorizationRequestResolver]
     */
    private val proxy: AuthorizationRequestResolver by lazy {
        createResolver(walletOpenId4VPConfig, httpClient)
    }

    override suspend fun resolveRequest(request: AuthorizationRequest) =
        proxy.resolveRequest(request)

    override fun close() = httpClient.close()

}


private fun createResolver(
    walletOpenId4VPConfig: WalletOpenId4VPConfig,
    httpClient: HttpClient
): AuthorizationRequestResolver =
    DefaultAuthorizationRequestResolver.make(
        getClientMetaData = HttpKtorAdapter.httpGet(httpClient),
        getPresentationDefinition = HttpKtorAdapter.httpGet(httpClient),
        getRequestObjectJwt = { url ->
            runCatching {
                httpClient.get(url) {
                    accept(ContentType.parse("application/oauth-authz-req+jwt"))
                }.bodyAsText()
            }
        },
        walletOpenId4VPConfig = walletOpenId4VPConfig
    )

