package eu.europa.ec.euidw.openid4vp

import io.ktor.client.*
import io.ktor.client.call.*
import io.ktor.client.plugins.contentnegotiation.*
import io.ktor.client.request.*
import io.ktor.http.*
import io.ktor.serialization.kotlinx.json.*
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.put
import java.net.URLEncoder

suspend fun main() {
    val uri = createHttpClient().use { client ->
        val initTransactionResponse = initTransaction(client).also { println(it) }
        formatURI(initTransactionResponse).also { println("Uri:${it}") }
    }
    resolver().use { resolver ->
        resolver.resolveRequestUri(uri).also { println(it) }
    }
}


private suspend fun initTransaction(client: HttpClient): JsonObject =
    client.post(" http://localhost:8080/ui/presentations") {
        contentType(ContentType.Application.Json)
        accept(ContentType.Application.Json)
        setBody(buildJsonObject {
            put("type", "id_token")
            put("id_token_type", "subject_signed_id_token")
        })

    }.body<JsonObject>()

private fun formatURI(iniTransactionResponse: JsonObject): String {
    val clientId = iniTransactionResponse["client_id"]!!.jsonPrimitive.content
    val requestUri = iniTransactionResponse["request_uri"]!!.jsonPrimitive.content

    return "eudi-wallet://authorize?client_id=${clientId}&request_uri=${URLEncoder.encode(requestUri, "UTF-8")}"
}


private fun resolver(): ManagedAuthorizationRequestResolver {
    val walletConfig = WalletOpenId4VPConfig(
        presentationDefinitionUriSupported = true,
        supportedClientIdScheme = SupportedClientIdScheme.IsoX509,
        vpFormatsSupported = emptyList(),
        subjectSyntaxTypesSupported = emptyList()
    )
    return ManagedAuthorizationRequestResolver.ktor(walletConfig)
}

private fun createHttpClient(): HttpClient = HttpClient {
    install(ContentNegotiation) { json() }
    expectSuccess = true
}

