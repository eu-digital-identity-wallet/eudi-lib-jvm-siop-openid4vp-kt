package eu.europa.ec.eudi.openid4vp

import eu.europa.ec.eudi.openid4vp.internal.dispatch.DefaultDispatcher
import eu.europa.ec.eudi.openid4vp.internal.request.DefaultAuthorizationRequestResolver
import io.ktor.client.*
import io.ktor.client.call.*
import io.ktor.client.plugins.contentnegotiation.*
import io.ktor.client.request.*
import io.ktor.client.request.forms.*
import io.ktor.client.statement.*
import io.ktor.http.*
import io.ktor.serialization.kotlinx.json.*
import java.net.URL

/**
 * Alias of a  method that creates a [HttpClient]
 */
typealias KtorHttpClientFactory = () -> HttpClient

/**
 * An implementation of [SiopOpenId4Vp] that uses Ktor
 *
 */
class SiopOpenId4VpKtor(
    private val walletOpenId4VPConfig: WalletOpenId4VPConfig,
    private val httpClientFactory: KtorHttpClientFactory = DefaultFactory,
) : SiopOpenId4Vp {

    override suspend fun resolveRequest(request: AuthorizationRequest): Resolution =
        authorizationResolver(walletOpenId4VPConfig, httpClientFactory).resolveRequest(request)

    override suspend fun build(requestObject: ResolvedRequestObject, consensus: Consensus): AuthorizationResponse =
        AuthorizationResponseBuilder.Default.build(requestObject, consensus)

    override suspend fun dispatch(response: AuthorizationResponse): DispatchOutcome =
        dispatcher(httpClientFactory).dispatch(response)

    companion object {

        /**
         * Factory which produces a [Ktor Http client][HttpClient]
         * The actual engine will be peeked up by whatever
         * is available in classpath
         *
         * @see [Ktor Client]("https://ktor.io/docs/client-dependencies.html#engine-dependency)
         */
        val DefaultFactory: KtorHttpClientFactory = {
            HttpClient {
                install(ContentNegotiation) { json() }
                expectSuccess = true
            }
        }

        /**
         * Factory method for creating an [AuthorizationRequestResolver] that
         * uses the provided [KtorHttpClientFactory] to obtain a [HttpClient]
         * which in turn is used, if needed, to contact the verifier's end-points
         *
         * The [AuthorizationRequestResolver] will obtain a new [HttpClient] with each call & then release it
         *
         * @param walletOpenId4VPConfig wallet configuration
         * @param httpClientFactory factory to obtain [HttpClient]
         * @return an [AuthorizationRequestResolver] as described above
         *
         * @see DefaultAuthorizationRequestResolver
         */
        fun authorizationResolver(
            walletOpenId4VPConfig: WalletOpenId4VPConfig,
            httpClientFactory: KtorHttpClientFactory = DefaultFactory,
        ): AuthorizationRequestResolver {
            fun createResolver(c: HttpClient) = DefaultAuthorizationRequestResolver.make(
                getClientMetaData = httpGet(c),
                getPresentationDefinition = httpGet(c),
                getRequestObjectJwt = { url ->
                    runCatching {
                        c.get(url) {
                            accept(ContentType.parse("application/oauth-authz-req+jwt"))
                        }.bodyAsText()
                    }
                },
                walletOpenId4VPConfig = walletOpenId4VPConfig,
            )
            return AuthorizationRequestResolver { request ->
                httpClientFactory().use { client ->
                    createResolver(client).resolveRequest(request)
                }
            }
        }

        /**
         * A factory method for creating an instance of [HttpGet] that delegates HTTP
         * calls to [httpClient]
         *
         * @param R the type of the body
         * @return an [HttpGet] implemented via [ktor][HttpClient]
         *
         */
        private inline fun <reified R> httpGet(httpClient: HttpClient): HttpGet<R> =
            object : HttpGet<R> {
                override suspend fun get(url: URL): Result<R> = runCatching {
                    httpClient.get(url).body<R>()
                }
            }

        /**
         * Factory method for creating an [Dispatcher] that
         * uses the provided [KtorHttpClientFactory] to obtain a [HttpClient]
         * which in turn is used, if needed, to contact the verifier's end-points.
         *
         * The [Dispatcher] will obtain a new [HttpClient] with each call & then release it
         *
         * @param httpClientFactory factory to obtain [HttpClient]
         * @return the [Dispatcher] as described above
         * @see DefaultDispatcher
         */
        fun dispatcher(httpClientFactory: KtorHttpClientFactory = DefaultFactory): Dispatcher {
            fun createDispatcher(c: HttpClient) = DefaultDispatcher { url, parameters ->
                runCatching {
                    val response = c.submitForm(
                        url = url.toString(),
                        formParameters = Parameters.build {
                            parameters.entries.forEach { append(it.key, it.value) }
                        },
                    )
                    if (response.status == HttpStatusCode.OK) {
                        DispatchOutcome.VerifierResponse.Accepted(null)
                    } else DispatchOutcome.VerifierResponse.Rejected
                }.getOrElse { DispatchOutcome.VerifierResponse.Rejected }
            }

            return Dispatcher { response ->
                httpClientFactory().use { client ->
                    createDispatcher(client).dispatch(response)
                }
            }
        }
    }
}
