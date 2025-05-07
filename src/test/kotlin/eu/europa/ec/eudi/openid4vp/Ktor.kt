package eu.europa.ec.eudi.openid4vp

import io.ktor.client.*
import io.ktor.client.engine.*
import io.ktor.client.plugins.logging.*

object LoggingHttpClientFactory {
    fun createLoggingHttpClient(loggerImpl: Logger = Logger.SIMPLE, loggerLevel: LogLevel = LogLevel.HEADERS, httpEngine: HttpClientEngine): HttpClient =
        HttpClient(httpEngine) {
            install(Logging){
                logger = loggerImpl
                level = loggerLevel
            }
        }
    }
