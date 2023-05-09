package eu.europa.ec.euidw.openid4vp.internal

import io.ktor.client.*
import io.ktor.client.call.*
import io.ktor.client.engine.okhttp.*
import io.ktor.client.plugins.contentnegotiation.*
import io.ktor.client.request.*
import java.net.URL

internal fun interface HttpGet<out R> {
    suspend fun get(url: HttpsUrl): Result<R>

    companion object {
        inline fun <reified R> ktor(
            client: HttpClient = ktorHttpClient
        ): HttpGet<R> = object : HttpGet<R> {
            override suspend fun get(url: HttpsUrl): Result<R> = runCatching {
                client.use { it.get(url.value).body() }
            }
        }
    }
}


internal val ktorHttpClient: HttpClient by lazy {
    HttpClient(OkHttp) {
        install(ContentNegotiation) {}
        expectSuccess = true
    }
}

/**
 * Represents an HTTPS URL
 */
@JvmInline
value class HttpsUrl private constructor(val value: URL) {
//    init {
//        require("https" == value.protocol) { "Only https is supported" }
//    }

    companion object {
        fun make(s: String): Result<HttpsUrl> = runCatching { HttpsUrl(URL(s)) }
        fun make(url: URL): Result<HttpsUrl> = runCatching { HttpsUrl(url) }
    }
}