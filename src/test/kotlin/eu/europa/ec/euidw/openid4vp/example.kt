package eu.europa.ec.euidw.openid4vp

import eu.europa.ec.euidw.openid4vp.internal.createHttpClient
import io.ktor.client.*
import io.ktor.client.call.*
import io.ktor.client.request.*
import io.ktor.http.*
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.runInterruptible
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.put
import java.net.URLEncoder

suspend fun main() {
    createHttpClient().use { client ->
        val initTransactionResponse =  initTransaction(client).also { println(it) }
        val authRequestStr = formatURI(initTransactionResponse).also { println("Uri:${it}") }
        resolveRequest(client, authRequestStr).also { println(it) }
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


private suspend fun resolveRequest(client: HttpClient, uri: String) = resolver(client).resolveRequest(uri).getOrThrow()

private fun resolver(client: HttpClient): AuthorizationRequestResolver {
    val walletConfig = WalletOpenId4VPConfig(
        presentationDefinitionUriSupported = true,
        supportedClientIdScheme = SupportedClientIdScheme.IsoX509,
        vpFormatsSupported = emptyList()
    )
    return AuthorizationRequestResolver.make(client, walletConfig)
}

