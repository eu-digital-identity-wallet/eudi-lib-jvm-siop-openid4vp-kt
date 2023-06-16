/*
 * Copyright (c) 2023 European Commission
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package eu.europa.ec.eudi.openid4vp

import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.jwk.RSAKey
import com.nimbusds.openid.connect.sdk.Nonce
import com.nimbusds.openid.connect.sdk.claims.IDTokenClaimsSet
import io.ktor.client.*
import io.ktor.client.call.*
import io.ktor.client.engine.okhttp.*
import io.ktor.client.plugins.contentnegotiation.*
import io.ktor.client.request.*
import io.ktor.http.*
import io.ktor.serialization.kotlinx.json.*
import kotlinx.coroutines.*
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.jsonPrimitive
import java.net.URI
import java.net.URLEncoder
import java.security.SecureRandom
import java.security.cert.X509Certificate
import java.security.interfaces.RSAPublicKey
import javax.net.ssl.HostnameVerifier
import javax.net.ssl.SSLContext
import javax.net.ssl.TrustManager
import javax.net.ssl.X509TrustManager

/**
 * Examples assumes that you have cloned and running
 * https://github.com/eu-digital-identity-wallet/eudi-srv-web-verifier-endpoint-23220-4-kt
 */
fun main(): Unit = runBlocking {
    val walletKeyPair = SiopIdTokenBuilder.randomKey()

    val holder = HolderInfo("walletHolder@foo.bar.com", "Wallet Holder")

    val wallet = Wallet(
        walletKeyPair = walletKeyPair,
        holder = holder,
        walletConfig = cfg(verifierPreregisteredMetaData),
    )
    val verifier = Verifier.make(walletKeyPair.toRSAPublicKey(), randomNonce())

    wallet.handle(verifier.authorizationRequestUri)

    verifier.getWalletResponse()
}

private fun randomNonce(): String = Nonce().value

private const val VerifierApi = "http://localhost:8080"
private val verifierPreregisteredMetaData = PreregisteredClient(
    "Verifier",
    JWSAlgorithm.RS256.name,
    JwkSetSource.ByReference(URI("$VerifierApi/wallet/public-keys.json")),
)

/**
 * This class is a minimal Verifier / RP application
 */
class Verifier private constructor(
    private val walletPublicKey: RSAPublicKey,
    private val presentationId: String,
    private val nonce: String,
    val authorizationRequestUri: URI,
) {

    override fun toString(): String =
        "Verifier presentationId=$presentationId, authorizationRequestUri=$authorizationRequestUri"

    suspend fun getWalletResponse(): IDTokenClaimsSet? {
        val walletResponse = createHttpClient().use {
            it.get("$VerifierApi/ui/presentations/$presentationId?nonce=$nonce") {
                accept(ContentType.Application.Json)
            }
        }.body<JsonObject>()

        val idTokenClaims = walletResponse["id_token"]?.jsonPrimitive?.content?.let {
            val claims = SiopIdTokenBuilder.decodeAndVerify(
                it,
                walletPublicKey,
            )
            IDTokenClaimsSet(claims)
        }
        return idTokenClaims.also { verifierPrintln("Got id_token with payload $idTokenClaims") }
    }

    companion object {

        /**
         * Creates a new verifier that knows (out of bound) the
         * wallet's public key
         */
        suspend fun make(walletPublicKey: RSAPublicKey, nonce: String): Verifier = coroutineScope {
            verifierPrintln("Initializing Verifier ...")
            withContext(Dispatchers.IO + CoroutineName("wallet-initTransaction")) {
                createHttpClient().use { client ->
                    val initTransactionResponse = initSiopTransaction(client, nonce)
                    val presentationId = initTransactionResponse["presentation_id"]!!.jsonPrimitive.content
                    val uri = formatAuthorizationRequest(initTransactionResponse)
                    Verifier(walletPublicKey, presentationId, nonce, uri).also { verifierPrintln("Initialized $it") }
                }
            }
        }

        private suspend fun initSiopTransaction(client: HttpClient, nonce: String): JsonObject {
            verifierPrintln("Placing to verifier endpoint  SIOP authentication request ...")
            val request =
                """
                    {
                        "type": "id_token",
                        "nonce": "$nonce",
                        "id_token_type": "subject_signed_id_token"    
                    }
                """.trimIndent()
            return initTransaction(client, request)
        }

        private suspend fun initOpenId4VpTransaction(
            client: HttpClient,
            nonce: String,
            presentationDefinition: String,
        ): JsonObject {
            verifierPrintln("Placing to verifier endpoint OpenId4Vp authorization request  ...")
            val request =
                """
                    {
                        "type": "vp_token",
                        "nonce": "$nonce",
                        "presentation_definition": $presentationDefinition    
                    }
                """.trimIndent()
            return initTransaction(client, request)
        }

        private suspend inline fun <reified B> initTransaction(client: HttpClient, body: B): JsonObject =
            client.post("$VerifierApi/ui/presentations") {
                contentType(ContentType.Application.Json)
                accept(ContentType.Application.Json)
                setBody(body)
            }.body<JsonObject>()

        private fun formatAuthorizationRequest(iniTransactionResponse: JsonObject): URI {
            fun String.encode() = URLEncoder.encode(this, "UTF-8")
            val clientId = iniTransactionResponse["client_id"]?.jsonPrimitive?.content?.encode()!!
            val requestUri = iniTransactionResponse["request_uri"]?.jsonPrimitive?.content?.encode()!!
            return URI("eudi-wallet://authorize?client_id=$clientId&request_uri=$requestUri")
        }

        private fun verifierPrintln(s: String) = println("Verifier : $s")
    }
}

private class Wallet(
    private val holder: HolderInfo,
    private val walletConfig: WalletOpenId4VPConfig,
    private val walletKeyPair: RSAKey,
) {

    private val siopOpenId4Vp: SiopOpenId4Vp by lazy {
        SiopOpenId4Vp.ktor(walletConfig) { createHttpClient() }
    }

    suspend fun handle(uri: URI): DispatchOutcome {
        walletPrintln("Handling $uri ...")
        return withContext(Dispatchers.IO) {
            siopOpenId4Vp.handle(uri.toString()) { holderConsent(it) }.also {
                walletPrintln("Response was sent to verifierApi which replied with $it")
            }
        }
    }

    suspend fun holderConsent(request: ResolvedRequestObject): Consensus = withContext(Dispatchers.Default) {
        when (request) {
            is ResolvedRequestObject.SiopAuthentication -> {
                walletPrintln("Received an SiopAuthentication request")
                fun showScreen() = true.also {
                    walletPrintln("User consensus was $it")
                }

                val userConsent: Boolean = showScreen()
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

    companion object {
        fun walletPrintln(s: String) = println("Wallet   : $s")
    }
}

private fun createHttpClient(): HttpClient = HttpClient(OkHttp) {
    engine {
        config {
            sslSocketFactory(SslSettings.sslContext().socketFactory, SslSettings.trustManager())
            hostnameVerifier(SslSettings.hostNameVerifier())
        }
    }
    install(ContentNegotiation) { json() }

    expectSuccess = true
}

object SslSettings {

    fun sslContext(): SSLContext {
        val sslContext = SSLContext.getInstance("TLS")
        sslContext.init(null, arrayOf(trustManager()), SecureRandom())
        return sslContext
    }

    fun hostNameVerifier(): HostnameVerifier = TrustAllHosts
    fun trustManager(): X509TrustManager = TrustAllCerts as X509TrustManager

    private var TrustAllCerts: TrustManager = object : X509TrustManager {
        override fun checkClientTrusted(chain: Array<X509Certificate>, authType: String) {}
        override fun checkServerTrusted(chain: Array<X509Certificate>, authType: String) {}
        override fun getAcceptedIssuers(): Array<X509Certificate> {
            return arrayOf()
        }
    }
    private val TrustAllHosts: HostnameVerifier = HostnameVerifier { _, _ -> true }
}

private fun cfg(verifierMetaData: PreregisteredClient) = WalletOpenId4VPConfig(
    presentationDefinitionUriSupported = true,
    supportedClientIdSchemes = listOf(SupportedClientIdScheme.Preregistered(mapOf(verifierMetaData.clientId to verifierMetaData))),
    vpFormatsSupported = emptyList(),
    subjectSyntaxTypesSupported = emptyList(),
)
