package eu.europa.ec.euidw.openid4vp

import com.nimbusds.jose.jwk.RSAKey
import io.ktor.client.*
import io.ktor.client.call.*
import io.ktor.client.plugins.contentnegotiation.*
import io.ktor.client.request.*
import io.ktor.http.*
import io.ktor.serialization.kotlinx.json.*
import kotlinx.coroutines.*
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.put
import java.net.URI
import java.net.URLEncoder

fun main(): Unit = runBlocking {

    val (presentationId, uri) = VerifierApp.initTransaction()
    Wallet().handle(uri).also { println(it) }

    VerifierApp.getWalletResponse(presentationId).also { println(it) }

}

object VerifierApp {

    suspend fun initTransaction(): Pair<String, URI> = coroutineScope {
        val jobName = CoroutineName("wallet-initTransaction")
        withContext(Dispatchers.IO + jobName) {
            createHttpClient().use { client ->
                val initTransactionResponse = initTransaction(client).also { println(it) }
                initTransactionResponse["presentation_id"]!!.jsonPrimitive.content to formatURI(initTransactionResponse).also { println("Uri:${it}") }
            }
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

    private fun formatURI(iniTransactionResponse: JsonObject): URI {
        val clientId = iniTransactionResponse["client_id"]!!.jsonPrimitive.content
        val requestUri = iniTransactionResponse["request_uri"]!!.jsonPrimitive.content
        return URI(
            "eudi-wallet://authorize?client_id=${clientId}&request_uri=${
                URLEncoder.encode(
                    requestUri,
                    "UTF-8"
                )
            }"
        )
    }

    suspend fun getWalletResponse(presentationId: String) : JsonObject{
        return createHttpClient().use {
            it.get("http://localhost:8080/ui/presentations/$presentationId") {
                accept(ContentType.Application.Json)
            }
        }.body<JsonObject>()
    }
    private fun createHttpClient(): HttpClient = HttpClient {
        install(ContentNegotiation) { json() }
        expectSuccess = true
    }
}

private class Wallet(
    private val holder : IdToken = IdToken(
        holderEmail = "foo@bar.com",
        holderName = "Foo Bar"
    ),
    private val walletConfig: WalletOpenId4VPConfig = DefaultConfig,
    private val walletKeyPair : RSAKey = SiopIdTokenBuilder.randomKey()
) {




    suspend fun handle(uri: URI): DispatchOutcome =
        withContext(Dispatchers.IO) {
            SiopOpenId4Vp.handle(walletConfig, uri.toString()) { holderConsent(it) }
        }

    suspend fun holderConsent(request: ResolvedRequestObject): Consensus = withContext(Dispatchers.Default) {
        when (request) {
            is ResolvedRequestObject.SiopAuthentication -> {

                fun showScreen() = true

                val userConsent: Boolean = showScreen();
                if (userConsent) {
                    val idToken = SiopIdTokenBuilder.build(request, holder,  walletConfig, walletKeyPair)
                    Consensus.PositiveConsensus.IdTokenConsensus(idToken)
                } else {
                    Consensus.NegativeConsensus
                }
            }

            else -> Consensus.NegativeConsensus
        }
    }
}

private val DefaultConfig = WalletOpenId4VPConfig(
    presentationDefinitionUriSupported = true,
    supportedClientIdScheme = SupportedClientIdScheme.IsoX509,
    vpFormatsSupported = emptyList(),
    subjectSyntaxTypesSupported = emptyList()
)







