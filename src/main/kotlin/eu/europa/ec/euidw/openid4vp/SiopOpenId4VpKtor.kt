package eu.europa.ec.euidw.openid4vp


import eu.europa.ec.euidw.openid4vp.internal.dispatch.DefaultDispatcher
import eu.europa.ec.euidw.openid4vp.internal.request.DefaultAuthorizationRequestResolver
import io.ktor.client.*
import io.ktor.client.call.*
import io.ktor.client.plugins.contentnegotiation.*
import io.ktor.client.request.*
import io.ktor.client.request.forms.*
import io.ktor.client.statement.*
import io.ktor.http.*
import io.ktor.serialization.kotlinx.json.*
import java.net.URL

typealias KtorHttpClientFactory = () -> HttpClient

class SiopOpenId4VpKtor(
    private val walletOpenId4VPConfig: WalletOpenId4VPConfig,
    private val httpClientFactory: KtorHttpClientFactory = DefaultFactory
) : SiopOpenId4Vp {

    override suspend fun resolveRequest(request: AuthorizationRequest): Resolution =
        authorizationResolver(walletOpenId4VPConfig, httpClientFactory).resolveRequest(request)

    override suspend fun build(requestObject: ResolvedRequestObject, consensus: Consensus): AuthorizationResponse =
        AuthorizationResponseBuilder.Default.build(requestObject, consensus)

    override suspend fun dispatch(response: AuthorizationResponse): DispatchOutcome =
        dispatcher(httpClientFactory).dispatch(response)

    companion object {
        val DefaultFactory: KtorHttpClientFactory = { createKtorClient() }
        fun authorizationResolver(
            walletOpenId4VPConfig: WalletOpenId4VPConfig,
            httpClientFactory: KtorHttpClientFactory = DefaultFactory
        ): AuthorizationRequestResolver = AuthorizationRequestResolver { request ->
            httpClientFactory().use { client ->
                createResolver(walletOpenId4VPConfig, client).resolveRequest(request)
            }
        }

        fun dispatcher(httpClientFactory: KtorHttpClientFactory = DefaultFactory): Dispatcher =
            Dispatcher { response ->
                httpClientFactory().use { client ->
                    DefaultDispatcher(httpFormPost(client)).dispatch(response)
                }
            }
    }

}

private fun createResolver(
    walletOpenId4VPConfig: WalletOpenId4VPConfig,
    httpClient: HttpClient
): AuthorizationRequestResolver =
    DefaultAuthorizationRequestResolver.make(
        getClientMetaData = httpGet(httpClient),
        getPresentationDefinition = httpGet(httpClient),
        getRequestObjectJwt = { url ->
            runCatching {
                httpClient.get(url) {
                    accept(ContentType.parse("application/oauth-authz-req+jwt"))
                }.bodyAsText()
            }
        },
        walletOpenId4VPConfig = walletOpenId4VPConfig
    )

/**
 * A factory method for creating an instance of [HttpFormPost] that delegates HTTP
 * calls to [httpClient]
 */
private fun httpFormPost(httpClient: HttpClient): HttpFormPost<DispatchOutcome.VerifierResponse> =
    HttpFormPost { url, parameters ->
        try {
            val response = httpClient.submitForm(
                url = url.toString(),
                formParameters = Parameters.build {
                    parameters.entries.forEach { append(it.key, it.value) }
                }
            )
            if (response.status == HttpStatusCode.OK) DispatchOutcome.VerifierResponse.Accepted(null)
            else DispatchOutcome.VerifierResponse.Rejected
        } catch (e: Throwable) {
            DispatchOutcome.VerifierResponse.Rejected
        }
    }

/**
 * A factory method for creating an instance of [HttpGet] that delegates HTTP
 * calls to [httpClient]
 */
private inline fun <reified R> httpGet(httpClient: HttpClient): HttpGet<R> =
    object : HttpGet<R> {
        override suspend fun get(url: URL): Result<R> = runCatching {
            httpClient.get(url).body<R>()
        }
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