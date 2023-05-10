package eu.europa.ec.euidw.openid4vp.internal

import eu.europa.ec.euidw.openid4vp.HttpGet
import io.ktor.client.*
import io.ktor.client.call.*
import io.ktor.client.plugins.contentnegotiation.*
import io.ktor.client.request.*
import io.ktor.serialization.kotlinx.json.*

internal fun createHttpClient(): HttpClient = HttpClient {
    install(ContentNegotiation) { json() }
    expectSuccess = true
}

inline fun <reified R> ktor(httpClient: HttpClient): HttpGet<R> =
    HttpGet { url -> httpClient.get(url.value).body() }