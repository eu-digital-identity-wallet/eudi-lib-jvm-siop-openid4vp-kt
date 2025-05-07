package eu.europa.ec.eudi.openid4vp

import io.ktor.client.*
import io.ktor.client.plugins.logging.*

object LoggingHttpClientFactory {
    fun createLoggingHttpClient(logging:Boolean = false,loggerImpl: Logger = Logger.SIMPLE, loggerLevel: LogLevel = LogLevel.HEADERS): HttpClient =
        HttpClient {
            if(logging) {
                install(Logging){
                    logger = loggerImpl
                    level = loggerLevel
                }
            }else {}
        }
    }
