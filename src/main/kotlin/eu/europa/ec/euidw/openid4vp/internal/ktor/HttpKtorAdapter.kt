package eu.europa.ec.euidw.openid4vp.internal.ktor

import eu.europa.ec.euidw.openid4vp.DispatchOutcome
import eu.europa.ec.euidw.openid4vp.HttpFormPost
import eu.europa.ec.euidw.openid4vp.HttpGet
import io.ktor.client.*
import io.ktor.client.call.*
import io.ktor.client.plugins.contentnegotiation.*
import io.ktor.client.request.*
import io.ktor.client.request.forms.*
import io.ktor.client.statement.*
import io.ktor.http.*
import io.ktor.serialization.kotlinx.json.*
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.jsonObject
import java.net.URL



internal object HttpKtorAdapter {

    /**
     * Factory method for creating a Ktor Http client
     * The actual engine will be peeked up by whatever
     * is available in classpath
     *
     * @see <a href="https://ktor.io/docs/client-dependencies.html#engine-dependency">Ktor Client</a>
     */
    internal fun createKtorClient(): HttpClient =
        HttpClient {
            install(ContentNegotiation) { json() }
            expectSuccess = true
        }

    /**
     * A factory method for creating an instance of [HttpGet] that delegates HTTP
     * calls to [httpClient]
     */
    internal inline fun <reified R> httpGet(httpClient: HttpClient): HttpGet<R> =
        object : HttpGet<R> {
            override suspend fun get(url: URL): Result<R> = runCatching {
                httpClient.get(url).body<R>()
            }
        }

//    /**
//     * A factory method for creating an instance of [HttpFormPost] that delegates HTTP
//     * calls to [httpClient]
//     */
//    internal fun <R>httpFormPost(httpClient: HttpClient, onError: ()->R, tx: (JsonObject)->R ): HttpFormPost<R> =
//        HttpFormPost { url, parameters ->
//            try {
//                val response = httpClient.submitForm(
//                    url = url.toString(),
//                    formParameters = Parameters.build {
//                        parameters.entries.forEach { append(it.key, it.value) }
//                    }
//                )
//                if(response.status== 200)
//            }catch (e : Throwable) {
//                e.printStackTrace()
//                onError()
//            }
//
//        }



    internal fun httpFormPost(httpClient: HttpClient ): HttpFormPost<DispatchOutcome.VerifierResponse> =
        HttpFormPost { url, parameters ->
            try {
                val response = httpClient.submitForm(
                    url = url.toString(),
                    formParameters = Parameters.build {
                        parameters.entries.forEach { append(it.key, it.value) }
                    }
                )
                if(response.status== HttpStatusCode.OK) DispatchOutcome.VerifierResponse.Accepted(null)
                else DispatchOutcome.VerifierResponse.Rejected
            }catch (e : Throwable) {
                DispatchOutcome.VerifierResponse.Rejected
            }

        }
}
