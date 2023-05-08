package eu.europa.ec.euidw.openid4vp.internal.utils

import java.net.URL

fun interface HttpGet<R> {
    suspend fun get(url: HttpsUrl): Result<R>
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