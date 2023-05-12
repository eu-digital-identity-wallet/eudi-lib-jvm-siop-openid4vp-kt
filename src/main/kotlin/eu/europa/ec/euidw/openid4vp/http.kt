package eu.europa.ec.euidw.openid4vp

import java.net.URL

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


/**
 * An abstraction of an HTTP Get operation
 * to obtain [R]
 */
fun interface HttpGet<out R> {
    suspend fun get(url: URL): Result<R>
}

fun interface HttpFormPost {
    suspend fun post(url: URL, formParameters : Map<String, String>) : String
}