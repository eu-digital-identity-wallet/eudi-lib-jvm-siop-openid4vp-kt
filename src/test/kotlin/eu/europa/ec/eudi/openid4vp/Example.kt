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

import com.nimbusds.jose.EncryptionMethod
import com.nimbusds.jose.JWEAlgorithm
import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.jwk.JWKSet
import com.nimbusds.jose.jwk.RSAKey
import com.nimbusds.openid.connect.sdk.Nonce
import com.nimbusds.openid.connect.sdk.claims.IDTokenClaimsSet
import eu.europa.ec.eudi.prex.*
import io.ktor.client.*
import io.ktor.client.call.*
import io.ktor.client.engine.okhttp.*
import io.ktor.client.plugins.contentnegotiation.*
import io.ktor.client.request.*
import io.ktor.http.*
import io.ktor.serialization.kotlinx.json.*
import kotlinx.coroutines.CoroutineName
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.test.runTest
import kotlinx.coroutines.withContext
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.contentOrNull
import kotlinx.serialization.json.jsonPrimitive
import java.net.URI
import java.net.URLEncoder
import java.security.KeyStore
import java.security.SecureRandom
import java.security.cert.X509Certificate
import javax.net.ssl.HostnameVerifier
import javax.net.ssl.SSLContext
import javax.net.ssl.TrustManager
import javax.net.ssl.X509TrustManager

/**
 * Examples assume that you have cloned and running
 * https://github.com/eu-digital-identity-wallet/eudi-srv-web-verifier-endpoint-23220-4-kt
 */
fun main(): Unit = runTest {
    val walletKeyPair = SiopIdTokenBuilder.randomKey()
    val wallet = Wallet(
        walletKeyPair = walletKeyPair,
        holder = HolderInfo("walletHolder@foo.bar.com", "Wallet Holder"),
        walletConfig = walletConfig(Verifier.X509SanDns, walletKeyPair),
    )

    suspend fun runUseCase(transaction: Transaction) {
        println("Running ${transaction.name} ...")
        val verifier = Verifier.make(
            walletPublicKey = wallet.pubKey,
            transaction = transaction,
        )
        wallet.handle(verifier.authorizationRequestUri)
        verifier.getWalletResponse()
    }

    runUseCase(Transaction.SIOP)
    runUseCase(Transaction.PidRequest)
}

@Serializable
data class WalletResponse(
    @SerialName("id_token") val idToken: String? = null,
    @SerialName("vp_token") val vpToken: String? = null,
    @SerialName("presentation_submission") val presentationSubmission: PresentationSubmission? = null,
    @SerialName("error") val error: String? = null,
)

fun WalletResponse.idTokenClaimSet(walletPublicKey: RSAKey): IDTokenClaimsSet? =
    idToken?.let { SiopIdTokenBuilder.decodeAndVerify(it, walletPublicKey).getOrThrow() }

/**
 * This class is a minimal Verifier / RP application
 */
class Verifier private constructor(
    private val walletPublicKey: RSAKey,
    private val presentationId: String,
    private val nonce: String,
    val authorizationRequestUri: URI,
) {

    override fun toString(): String =
        "Verifier presentationId=$presentationId, authorizationRequestUri=$authorizationRequestUri"

    suspend fun getWalletResponse(): WalletResponse {
        val walletResponse = createHttpClient().use {
            it.get("$VERIFIER_API/ui/presentations/$presentationId?nonce=$nonce") {
                accept(ContentType.Application.Json)
            }
        }.body<WalletResponse>()

        walletResponse.idTokenClaimSet(walletPublicKey)?.also { verifierPrintln("Got id_token with payload $it") }
        walletResponse.vpToken?.also { verifierPrintln("Got vp_token with payload $it") }
        walletResponse.presentationSubmission?.also { verifierPrintln("Got presentation_submission with payload $it") }
        return walletResponse
    }

    companion object {

        private const val VERIFIER_API = "http://localhost:8080"

        val PreregisteredClient: SupportedClientIdScheme.Preregistered by lazy {
            val client = PreregisteredClient(
                "Verifier",
                JWSAlgorithm.RS256.name,
                JwkSetSource.ByReference(URI("$VERIFIER_API/wallet/public-keys.json")),
            )

            SupportedClientIdScheme.Preregistered(mapOf(client.clientId to client))
        }

        val X509SanDns: SupportedClientIdScheme.X509SanDns by lazy {
            Verifier::class.java.classLoader.getResourceAsStream("certificates/certificates.jks")!!
                .use { inputStream ->
                    val keystore = KeyStore.getInstance(KeyStore.getDefaultType())
                    keystore.load(inputStream, "12345".toCharArray())

                    val trustedChain = keystore.getCertificateChain("verifier")
                        .orEmpty()
                        .map { it as X509Certificate }
                        .toList()
                        .also { trustedChain ->
                            check(trustedChain.size == 3) { "expected to load a trusted chain with 3 certificates " }
                        }

                    SupportedClientIdScheme.X509SanDns { untrustedChain -> untrustedChain == trustedChain }
                }
        }

        /**
         * Creates a new verifier that knows (out of bound) the
         * wallet's public key
         */
        suspend fun make(walletPublicKey: RSAKey, transaction: Transaction): Verifier = coroutineScope {
            verifierPrintln("Initializing Verifier ...")
            withContext(Dispatchers.IO + CoroutineName("wallet-initTransaction")) {
                createHttpClient().use { client ->
                    val nonce = randomNonce()
                    val initTransactionResponse = transaction.fold(
                        ifSiop = {
                            initSiopTransaction(client, nonce)
                        },
                        ifOpenId4VP = { presentationDefinition ->
                            initOpenId4VpTransaction(client, nonce, presentationDefinition)
                        },
                    )
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
                        "id_token_type": "subject_signed_id_token",
                        "response_mode": "direct_post.jwt",
                        "jar_mode": "by_reference"    
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
                        "presentation_definition": $presentationDefinition,
                        "response_mode": "direct_post.jwt" ,
                        "presentation_definition_mode": "by_reference"
                        "jar_mode": "by_value"       
                    }
                """.trimIndent()
            return initTransaction(client, request)
        }

        private suspend inline fun <reified B> initTransaction(client: HttpClient, body: B): JsonObject =
            client.post("$VERIFIER_API/ui/presentations") {
                contentType(ContentType.Application.Json)
                accept(ContentType.Application.Json)
                setBody(body)
            }.body<JsonObject>()

        private fun formatAuthorizationRequest(iniTransactionResponse: JsonObject): URI {
            fun String.encode() = URLEncoder.encode(this, "UTF-8")
            val clientId = iniTransactionResponse["client_id"]?.jsonPrimitive?.content?.encode()!!
            val requestUri =
                iniTransactionResponse["request_uri"]?.jsonPrimitive?.contentOrNull?.encode()?.let { "request_uri=$it" }
            val request = iniTransactionResponse["request"]?.jsonPrimitive?.contentOrNull?.let { "request=$it" }
            require(request != null || requestUri != null)
            val requestPart = requestUri ?: request
            return URI("eudi-wallet://authorize?client_id=$clientId&$requestPart")
        }

        private fun randomNonce(): String = Nonce().value

        private fun verifierPrintln(s: String) = println("Verifier : $s")
    }
}

sealed interface Transaction {

    val name: String
        get() = when (this) {
            is SIOP -> "SIOP"
            is OpenId4VP -> "OpenId4Vp"
        }

    data object SIOP : Transaction
    data class OpenId4VP(val presentationDefinition: String) : Transaction

    companion object {
        val PidRequest = OpenId4VP(PidPresentationDefinition)
    }
}

suspend fun <T> Transaction.fold(
    ifSiop: suspend () -> T,
    ifOpenId4VP: suspend (String) -> T,
): T = when (this) {
    Transaction.SIOP -> ifSiop()
    is Transaction.OpenId4VP -> ifOpenId4VP(presentationDefinition)
}

private class Wallet(
    private val holder: HolderInfo,
    private val walletConfig: WalletOpenId4VPConfig,
    private val walletKeyPair: RSAKey,
) {

    val pubKey: RSAKey
        get() = walletKeyPair.toPublicJWK()

    private val siopOpenId4Vp: SiopOpenId4Vp by lazy {
        SiopOpenId4Vp(walletConfig) { createHttpClient() }
    }

    suspend fun handle(uri: URI): DispatchOutcome {
        walletPrintln("Handling $uri ...")
        return withContext(Dispatchers.IO) {
            siopOpenId4Vp.handle(uri.toString()) { holderConsent(it) }.also {
                walletPrintln("Response was sent to verifierApi which replied with $it")
            }
        }
    }

    suspend fun SiopOpenId4Vp.handle(
        uri: String,
        holderConsensus: suspend (ResolvedRequestObject) -> Consensus,
    ): DispatchOutcome =
        when (val resolution = resolveRequestUri(uri)) {
            is Resolution.Invalid -> throw resolution.error.asException()
            is Resolution.Success -> {
                val requestObject = resolution.requestObject
                val consensus = holderConsensus(requestObject)
                val authorizationResponse = build(requestObject, consensus)
                dispatch(authorizationResponse)
            }
        }

    suspend fun holderConsent(request: ResolvedRequestObject): Consensus = withContext(Dispatchers.Default) {
        when (request) {
            is ResolvedRequestObject.SiopAuthentication -> handleSiop(request)
            is ResolvedRequestObject.OpenId4VPAuthorization -> handleOpenId4VP(request)
            else -> Consensus.NegativeConsensus
        }
    }

    @Suppress("KotlinConstantConditions")
    private fun handleSiop(request: ResolvedRequestObject.SiopAuthentication): Consensus {
        walletPrintln("Received an SiopAuthentication request")
        fun showScreen() = true.also {
            walletPrintln("User consensus was $it")
        }

        val userConsent: Boolean = showScreen()
        return if (userConsent) {
            val idToken = SiopIdTokenBuilder.build(request, holder, walletKeyPair)
            Consensus.PositiveConsensus.IdTokenConsensus(idToken)
        } else {
            Consensus.NegativeConsensus
        }
    }

    private fun handleOpenId4VP(request: ResolvedRequestObject.OpenId4VPAuthorization): Consensus {
        val presentationDefinition = request.presentationDefinition
        val inputDescriptor = presentationDefinition.inputDescriptors.first()
        return Consensus.PositiveConsensus.VPTokenConsensus(
            vpToken = "foo",
            presentationSubmission = PresentationSubmission(
                id = Id("pid-res"),
                definitionId = presentationDefinition.id,
                listOf(
                    DescriptorMap(
                        id = inputDescriptor.id,
                        format = ClaimFormat.MsoMdoc,
                        path = JsonPath.jsonPath("$")!!,
                    ),
                ),

            ),
        )
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

private fun walletConfig(supportedClientIdScheme: SupportedClientIdScheme, walletKeyPair: RSAKey) = WalletOpenId4VPConfig(
    presentationDefinitionUriSupported = true,
    supportedClientIdSchemes = listOf(supportedClientIdScheme),
    vpFormatsSupported = emptyList(),
    signingKeySet = JWKSet(walletKeyPair),
    holderId = "DID:example:12341512#$",
    authorizationSigningAlgValuesSupported = emptyList(),
    authorizationEncryptionAlgValuesSupported = listOf(JWEAlgorithm.parse("ECDH-ES")),
    authorizationEncryptionEncValuesSupported = listOf(EncryptionMethod.parse("A256GCM")),
)

val PidPresentationDefinition = """
            {
              "id": "pid-request",
              "input_descriptors": [
                {
                  "id": "pid",
                  "format": {
                    "mso_mdoc": {
                      "alg": [
                        "EdDSA",
                        "ES256"
                      ]
                    }
                  },
                  "constraints": {
                   
                    "fields": [
                      {
                        "path": [
                          "$.mdoc.doctype"
                        ],
                        "filter": {
                          "type": "string",
                          "const": "org.iso.18013.5.1.mDL"
                        }
                      },
                      {
                        "path": [
                          "$.mdoc.namespace"
                        ],
                        "filter": {
                          "type": "string",
                          "const": "org.iso.18013.5.1"
                        }
                      },
                      {
                        "path": [
                          "$.mdoc.family_name"
                        ],
                        "intent_to_retain": false
                      },
                      {
                        "path": [
                          "$.mdoc.portrait"
                        ],
                        "intent_to_retain": false
                      },
                      {
                        "path": [
                          "$.mdoc.driving_privileges"
                        ],
                        "intent_to_retain": false
                      }
                    ]
                  }
                }
              ]
            }
""".trimIndent()
