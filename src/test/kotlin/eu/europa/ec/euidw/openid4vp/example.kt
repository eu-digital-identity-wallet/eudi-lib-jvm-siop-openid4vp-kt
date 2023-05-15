package eu.europa.ec.euidw.openid4vp

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


    val uri = VerifierApp.initTransaction()
    val wallet = Wallet()
    val response = wallet.process(uri)

    println(response)


}

object VerifierApp {

    suspend fun initTransaction(): URI = coroutineScope {
        val jobName = CoroutineName("wallet-initTransaction")
        withContext(Dispatchers.IO + jobName) {
            createHttpClient().use { client ->
                val initTransactionResponse = initTransaction(client).also { println(it) }
                formatURI(initTransactionResponse).also { println("Uri:${it}") }
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

    private fun createHttpClient(): HttpClient = HttpClient {
        install(ContentNegotiation) { json() }
        expectSuccess = true
    }
}

private class Wallet(private val walletConfig: WalletOpenId4VPConfig = DefaultConfig) {


    suspend fun resolve(uri: URI): Resolution = withContext(Dispatchers.IO) {
        resolver().use { resolver ->
            resolver.resolveRequestUri(uri.toString()).also { println(it) }
        }
    }


    suspend fun process(uri: URI) = withContext(Dispatchers.IO){
        // Step 1 : wallet resolves the URI
        // Step 2 : if resolution is Success, wallet asks for holder's consent
        // Step 3 : wallet builds
        val resolution : Resolution = resolve(uri)
        val (request, consensus) = when (resolution) {
            is Resolution.Invalid -> {
                println("Invalid request ${resolution.error}")
                throw resolution.error.asException()
            }

            is Resolution.Success -> resolution.data to holderConsent(resolution.data)
        }
        val response = AuthorizationResponseBuilder.Default.build(request, consensus)
        val outcome = Dispatcher.Default.dispatch(response)


    }

    private fun resolver(): ManagedAuthorizationRequestResolver {
        return ManagedAuthorizationRequestResolver.ktor(walletConfig)
    }

    fun holderConsent(request: ResolvedRequestObject): Consensus {


        return when (request) {
            is ResolvedRequestObject.SiopAuthentication -> {

                fun showScreen() = true

                val userConsent: Boolean = showScreen();
                if (userConsent) {
                    val idToken = SiopIdTokenBuilder.build(request, walletConfig)
                    Consensus.PositiveConsensus.IdTokenConsensus(idToken)
                }else {
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







