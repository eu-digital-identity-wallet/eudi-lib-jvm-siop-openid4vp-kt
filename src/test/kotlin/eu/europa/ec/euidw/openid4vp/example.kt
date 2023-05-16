package eu.europa.ec.euidw.openid4vp

import com.nimbusds.jose.jwk.RSAKey
import com.nimbusds.jwt.JWTClaimsSet
import com.nimbusds.openid.connect.sdk.claims.IDTokenClaimsSet
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
import java.security.interfaces.RSAPublicKey

fun main(): Unit = runBlocking {

    val walletKeyPair = SiopIdTokenBuilder.randomKey()
    val holder = HolderInfo("walletHolder@foo.bar.com", "Wallet Holder")
    val wallet = Wallet(walletKeyPair = walletKeyPair, holder = holder)
    val verifier = VerifierApp.make(walletKeyPair.toRSAPublicKey())

    wallet.handle(verifier.uri)

    val idTokenClaims = verifier.getWalletResponse()


    println("Verifier got id_token with payload $idTokenClaims")
}

class VerifierApp private constructor(
    private val walletPublicKey: RSAPublicKey,
    val presentationId: String,
    val uri: URI
) {

    suspend fun getWalletResponse(): IDTokenClaimsSet? {
        val walletResponse = createHttpClient().use {
            it.get("http://localhost:8080/ui/presentations/${presentationId!!}") {
                accept(ContentType.Application.Json)
            }
        }.body<JsonObject>()

        val idTokenClaims = walletResponse["id_token"]?.jsonPrimitive?.content?.let {
            val claims = SiopIdTokenBuilder.decodeAndVerify(
                it,
                walletPublicKey
            )
            IDTokenClaimsSet(claims)
        }
        return idTokenClaims
    }

    companion object {


        suspend fun make(walletPublicKey: RSAPublicKey): VerifierApp = coroutineScope {
            val jobName = CoroutineName("wallet-initTransaction")
            withContext(Dispatchers.IO + jobName) {
                createHttpClient().use { client ->
                    val initTransactionResponse = make(client).also { println(it) }
                    val presentationId = initTransactionResponse["presentation_id"]!!.jsonPrimitive.content
                    val uri = formatURI(initTransactionResponse)
                    VerifierApp(walletPublicKey, presentationId, uri)
                }
            }
        }

        private suspend fun make(client: HttpClient): JsonObject =
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
}

private class Wallet(
    private val holder: HolderInfo,
    private val walletConfig: WalletOpenId4VPConfig = DefaultConfig,
    private val walletKeyPair: RSAKey
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
                    val idToken = SiopIdTokenBuilder.build(request, holder, walletConfig, walletKeyPair)
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







