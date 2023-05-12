package eu.europa.ec.euidw.openid4vp.internal.ktor

import eu.europa.ec.euidw.openid4vp.AuthorizationResponse
import eu.europa.ec.euidw.openid4vp.AuthorizationResponseDispatcher
import eu.europa.ec.euidw.openid4vp.HttpFormPost
import eu.europa.ec.euidw.openid4vp.ManagedAuthorizationResponseDispatcher
import eu.europa.ec.euidw.openid4vp.internal.dispatch.DirectPostResponseDispatcher
import io.ktor.client.*
import io.ktor.client.call.*
import io.ktor.client.plugins.contentnegotiation.*
import io.ktor.client.request.forms.*
import io.ktor.http.*
import io.ktor.serialization.kotlinx.json.*

class KtorDirectPostResponseDispatcher : ManagedAuthorizationResponseDispatcher {

    /**
     * The ktor http client
     */
    private val httpClient: HttpClient by lazy {
        createKtorClient()
    }

    /**
     * The actual or proxied [AuthorizationResponseDispatcher]
     */
    private val proxy: AuthorizationResponseDispatcher<AuthorizationResponse.DirectPostResponse, Unit> by lazy {
        DirectPostResponseDispatcher(httpFormPost = ktorAdapter(httpClient))
    }

    override suspend fun dispatch(response: AuthorizationResponse.DirectPostResponse) {
        proxy.dispatch(response)
    }

    override fun close() = httpClient.close()

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
}


/**
 * A factory method for creating an instance of [HttpFormPost] that delegates HTTP
 * calls to [httpClient]
 */
private fun ktorAdapter(httpClient: HttpClient): HttpFormPost =
    HttpFormPost { url, parameters ->
        val response = httpClient.submitForm(
            url = url.toString(),
            formParameters = parameters.toFormParameters()
        )
        response.body<String>()
    }

fun Map<String, String>.toFormParameters() : Parameters {
    return Parameters.build {
        this@toFormParameters.entries.forEach { append(it.key, it.value) }
    }
}