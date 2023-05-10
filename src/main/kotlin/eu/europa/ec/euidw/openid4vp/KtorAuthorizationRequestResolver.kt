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

class KtorAuthorizationRequestResolver(
    walletOpenId4VPConfig: WalletOpenId4VPConfig
) : AuthorizationRequestResolver, Closeable {

    private val httpClient: HttpClient by lazy { jsonHttpClient() }

    private val proxy: AuthorizationRequestResolver by lazy {
        AuthorizationRequestResolverImpl.make(
            getClientMetaData = ktor(httpClient),
            getPresentationDefinition = ktor(httpClient),
            getRequestObjectJwt = { url ->
                runCatching {
                    httpClient.get(url) { accept(ContentType.parse("application/oauth-authz-req+jwt")) }.bodyAsText()
                }
            },
            walletOpenId4VPConfig = walletOpenId4VPConfig
        )
    }

    override suspend fun resolveRequest(request: AuthorizationRequest) =
        proxy.resolveRequest(request)

    override suspend fun resolveRequestUri(uriStr: String): Result<ResolvedRequestObject> =
        proxy.resolveRequestUri(uriStr)

    override fun close() {
        httpClient.close()
    }

    private fun jsonHttpClient(): HttpClient = HttpClient {
        install(ContentNegotiation) { json() }
        expectSuccess = true
    }


}

private inline fun <reified R> ktor(httpClient: HttpClient): HttpGet<R> =
    object : HttpGet<R> {
        override suspend fun get(url: URL): Result<R> = runCatching {
            httpClient.get(url).body<R>()
        }
    }