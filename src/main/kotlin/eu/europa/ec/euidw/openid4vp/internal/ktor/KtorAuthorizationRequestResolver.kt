package eu.europa.ec.euidw.openid4vp.internal.ktor

import eu.europa.ec.euidw.openid4vp.*
import eu.europa.ec.euidw.openid4vp.internal.DefaultAuthorizationRequestResolver
import io.ktor.client.*
import io.ktor.client.call.*
import io.ktor.client.plugins.contentnegotiation.*
import io.ktor.client.request.*
import io.ktor.client.statement.*
import io.ktor.http.*
import io.ktor.serialization.kotlinx.json.*
import java.net.URL

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
    private val httpClient: HttpClient by lazy {
        createKtorClient()
    }

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

/**
 * Factory method for creating a Ktor Http client
 * The actual engine will be peeked up by whatever
 * is available in classpath
 *
 * @see <a href="https://ktor.io/docs/client-dependencies.html#engine-dependency">Ktor Client</a>
 */
private fun createKtorClient(): HttpClient =
    HttpClient {
        install(ContentNegotiation) { json() }
        expectSuccess = true
    }

private fun createResolver(
    walletOpenId4VPConfig: WalletOpenId4VPConfig,
    httpClient: HttpClient
): AuthorizationRequestResolver {

    return DefaultAuthorizationRequestResolver.make(
        getClientMetaData = ktorAdapter(httpClient),
        getPresentationDefinition = ktorAdapter(httpClient),
        getRequestObjectJwt = { url ->
            runCatching {
                httpClient.get(url) {
                    accept(ContentType.parse("application/oauth-authz-req+jwt"))
                }.bodyAsText()
            }
        },
        walletOpenId4VPConfig = walletOpenId4VPConfig
    )
}

/**
 * A factory method for creating an instance of [HttpGet] that delegates HTTP
 * calls to [httpClient]
 */
private inline fun <reified R> ktorAdapter(httpClient: HttpClient): HttpGet<R> =
    object : HttpGet<R> {
        override suspend fun get(url: URL): Result<R> = runCatching {
            httpClient.get(url).body<R>()
        }
    }