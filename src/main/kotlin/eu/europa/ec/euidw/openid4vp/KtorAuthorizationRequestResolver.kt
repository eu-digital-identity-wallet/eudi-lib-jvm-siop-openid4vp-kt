package eu.europa.ec.euidw.openid4vp

import eu.europa.ec.euidw.openid4vp.internal.AuthorizationRequestResolverImpl
import io.ktor.client.*
import io.ktor.client.call.*
import io.ktor.client.plugins.contentnegotiation.*
import io.ktor.client.request.*
import io.ktor.client.statement.*
import io.ktor.http.*
import io.ktor.serialization.kotlinx.json.*
import java.io.Closeable
import java.net.URL

/**
 * An implementation of [AuthorizationRequestResolver] which uses Ktor client
 *
 * Class implements also the [Closeable] interface so make sure that after using
 * the instance to either call [KtorAuthorizationRequestResolver.close] or use it via
 * [use] method
 */
class KtorAuthorizationRequestResolver(
    walletOpenId4VPConfig: WalletOpenId4VPConfig
) : AuthorizationRequestResolver, Closeable  {

    /**
     * The ktor http client
     */
    private val httpClient: HttpClient by lazy {
        HttpClient {
            install(ContentNegotiation) { json() }
            expectSuccess = true
        }
    }

    private val proxy: AuthorizationRequestResolver by lazy {
        AuthorizationRequestResolverImpl.make(
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

    override suspend fun resolveRequest(request: AuthorizationRequest) =
        proxy.resolveRequest(request)

    override fun close() {
        httpClient.close()
    }

}

/**
 * A factory method for creating an instance of [HttpGet] that delegates
 * calls to [httpClient]
 */
private inline fun <reified R> ktorAdapter(httpClient: HttpClient): HttpGet<R> =
    object : HttpGet<R> {
        override suspend fun get(url: URL): Result<R> = runCatching {
            httpClient.get(url).body<R>()
        }
    }