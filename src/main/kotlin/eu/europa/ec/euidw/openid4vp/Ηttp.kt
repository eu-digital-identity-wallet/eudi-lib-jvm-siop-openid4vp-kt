package eu.europa.ec.euidw.openid4vp

import eu.europa.ec.euidw.openid4vp.internal.mapError
import java.net.URI
import java.net.URL

/**
 * An abstraction of an HTTP Get operation
 * to obtain [R]
 */
fun interface HttpGet<out R> {
    suspend fun get(url: URL): Result<R>
}

fun interface HttpFormPost<out R> {
    suspend fun post(url: URL, formParameters: Map<String, String>): R
}

/**
 * Convenient method for parsing a string into a [URL]
 */
internal fun String.asURL(onError: (Throwable) -> Throwable = { it }): Result<URL> =
    runCatching { URL(this) }.mapError(onError)


/**
 * Convenient method for parsing a string into a [URI]
 */
internal fun String.asURI(onError: (Throwable) -> Throwable = { it }): Result<URI> =
    runCatching { URI(this) }.mapError(onError)