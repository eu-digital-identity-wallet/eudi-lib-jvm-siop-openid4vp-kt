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
import com.nimbusds.jose.jwk.RSAKey
import com.nimbusds.openid.connect.sdk.Nonce
import com.nimbusds.openid.connect.sdk.claims.IDTokenClaimsSet
import eu.europa.ec.eudi.openid4vp.SupportedClientIdScheme.Preregistered
import eu.europa.ec.eudi.openid4vp.SupportedClientIdScheme.X509SanDns
import eu.europa.ec.eudi.prex.*
import io.ktor.client.*
import io.ktor.client.call.*
import io.ktor.client.engine.okhttp.*
import io.ktor.client.plugins.contentnegotiation.*
import io.ktor.client.request.*
import io.ktor.http.*
import io.ktor.serialization.kotlinx.json.*
import kotlinx.coroutines.*
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.contentOrNull
import kotlinx.serialization.json.jsonPrimitive
import java.net.URI
import java.net.URL
import java.net.URLEncoder
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
fun main(): Unit = runBlocking {
    val verifierApi = URL("https://dev.verifier-backend.eudiw.dev")
    val walletKeyPair = SiopIdTokenBuilder.randomKey()
    val wallet = Wallet(
        walletKeyPair = walletKeyPair,
        holder = HolderInfo("walletHolder@foo.bar.com", "Wallet Holder"),
        walletConfig = walletConfig(
            Preregistered(Verifier.asPreregisteredClient(verifierApi)),
            X509SanDns(TrustAnyX509),
        ),
    )

    suspend fun runUseCase(transaction: Transaction) = coroutineScope {
        println("Running ${transaction.name} ...")
        val verifier = Verifier.make(
            verifierApi = verifierApi,
            walletPublicKey = wallet.pubKey,
            transaction = transaction,
        )

        when (val dispatchOutcome = wallet.handle(verifier.authorizationRequestUri)) {
            is DispatchOutcome.RedirectURI -> error("Unexpected")
            is DispatchOutcome.VerifierResponse.Accepted -> verifier.getWalletResponse(dispatchOutcome)
            DispatchOutcome.VerifierResponse.Rejected -> error("Unexpected failure")
        }
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
    private val verifierApi: URL,
    private val walletPublicKey: RSAKey,
    private val presentationId: String,
    val authorizationRequestUri: URI,
) {

    override fun toString(): String =
        "Verifier presentationId=$presentationId, authorizationRequestUri=$authorizationRequestUri"

    suspend fun getWalletResponse(dispatchOutcome: DispatchOutcome.VerifierResponse.Accepted): WalletResponse {
        val responseCode = Url(checkNotNull(dispatchOutcome.redirectURI)).parameters["response_code"]
        checkNotNull(responseCode) { "Failed to extract response_code" }

        val walletResponse = createHttpClient().use {
            it.get("$verifierApi/ui/presentations/$presentationId?response_code=$responseCode") {
                accept(ContentType.Application.Json)
            }
        }.body<WalletResponse>()

        walletResponse.idTokenClaimSet(walletPublicKey)?.also { verifierPrintln("Got id_token with payload $it") }
        walletResponse.vpToken?.also { verifierPrintln("Got vp_token with payload $it") }
        walletResponse.presentationSubmission?.also { verifierPrintln("Got presentation_submission with payload $it") }
        return walletResponse
    }

    companion object {

        fun asPreregisteredClient(verifierApi: URL): PreregisteredClient {
            return PreregisteredClient(
                "Verifier",
                JWSAlgorithm.RS256 to JwkSetSource.ByReference(URI("$verifierApi/wallet/public-keys.json")),
            )
        }

        /**
         * Creates a new verifier that knows (out of bound) the
         * wallet's public key
         */
        suspend fun make(verifierApi: URL, walletPublicKey: RSAKey, transaction: Transaction): Verifier =
            coroutineScope {
                verifierPrintln("Initializing Verifier ...")
                withContext(Dispatchers.IO + CoroutineName("wallet-initTransaction")) {
                    createHttpClient().use { client ->
                        val nonce = randomNonce()
                        val initTransactionResponse = transaction.fold(
                            ifSiop = {
                                initSiopTransaction(client, verifierApi, nonce)
                            },
                            ifOpenId4VP = { presentationDefinition ->
                                initOpenId4VpTransaction(client, verifierApi, nonce, presentationDefinition)
                            },
                        )
                        val presentationId = initTransactionResponse["presentation_id"]!!.jsonPrimitive.content
                        val uri = formatAuthorizationRequest(initTransactionResponse)
                        Verifier(verifierApi, walletPublicKey, presentationId, uri).also {
                            verifierPrintln("Initialized $it")
                        }
                    }
                }
            }

        private suspend fun initSiopTransaction(client: HttpClient, verifierApi: URL, nonce: String): JsonObject {
            verifierPrintln("Placing to verifier endpoint  SIOP authentication request ...")
            val request =
                """
                    {
                        "type": "id_token",
                        "nonce": "$nonce",
                        "id_token_type": "subject_signed_id_token",
                        "response_mode": "direct_post.jwt",
                        "jar_mode": "by_reference",
                        "wallet_response_redirect_uri_template":"https://foo?response_code={RESPONSE_CODE}"    
                    }
                """.trimIndent()
            return initTransaction(client, verifierApi, request)
        }

        private suspend fun initOpenId4VpTransaction(
            client: HttpClient,
            verifierApi: URL,
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
                        "jar_mode": "by_reference",
                        "wallet_response_redirect_uri_template":"https://foo?response_code={RESPONSE_CODE}"       
                    }
                """.trimIndent()
            return initTransaction(client, verifierApi, request)
        }

        private suspend inline fun <reified B> initTransaction(
            client: HttpClient,
            verifierApi: URL,
            body: B,
        ): JsonObject =
            client.post("$verifierApi/ui/presentations") {
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
    private val walletConfig: SiopOpenId4VPConfig,
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
                dispatch(requestObject, consensus)
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
            vpToken = VpToken.Generic("foo"),
            presentationSubmission = PresentationSubmission(
                id = Id("pid-res"),
                definitionId = presentationDefinition.id,
                listOf(
                    DescriptorMap(
                        id = inputDescriptor.id,
                        format = "mso_mdoc",
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

private val TrustAnyX509: (List<X509Certificate>) -> Boolean = { _ ->
    println("Warning!! Trusting any certificate. Do not use in production")
    true
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

private fun walletConfig(vararg supportedClientIdScheme: SupportedClientIdScheme) =
    SiopOpenId4VPConfig(
        jarmConfiguration = JarmConfiguration.Encryption(
            supportedAlgorithms = listOf(JWEAlgorithm.ECDH_ES),
            supportedMethods = listOf(EncryptionMethod.A128CBC_HS256, EncryptionMethod.A256GCM),
        ),
        supportedClientIdSchemes = supportedClientIdScheme,
    )

val PidPresentationDefinition = """
{
  "id": "pid-request",
  "input_descriptors": [
    {
      "id": "eu.europa.ec.eudiw.pid.1",
      "format": {
        "mso_mdoc": {
          "alg": [
            "ES256",
            "ES384",
            "ES512",
            "EdDSA"
          ]
        }
      },
      "name": "EUDI PID",
      "purpose": "We need to verify your identity",
      "constraints": {
        "fields": [
          {
            "path": [
              "$['eu.europa.ec.eudiw.pid.1']['family_name']"
            ],
            "intent_to_retain": false
          },
          {
            "path": [
              "$['eu.europa.ec.eudiw.pid.1']['given_name']"
            ],
            "intent_to_retain": false
          },
          {
            "path": [
              "$['eu.europa.ec.eudiw.pid.1']['birth_date']"
            ],
            "intent_to_retain": false
          },
          {
            "path": [
              "$['eu.europa.ec.eudiw.pid.1']['age_over_18']"
            ],
            "intent_to_retain": false
          },
          {
            "path": [
              "$['eu.europa.ec.eudiw.pid.1']['age_in_years']"
            ],
            "intent_to_retain": false
          },
          {
            "path": [
              "$['eu.europa.ec.eudiw.pid.1']['age_birth_year']"
            ],
            "intent_to_retain": false
          },
          {
            "path": [
              "$['eu.europa.ec.eudiw.pid.1']['family_name_birth']"
            ],
            "intent_to_retain": false
          },
          {
            "path": [
              "$['eu.europa.ec.eudiw.pid.1']['given_name_birth']"
            ],
            "intent_to_retain": false
          },
          {
            "path": [
              "$['eu.europa.ec.eudiw.pid.1']['birth_place']"
            ],
            "intent_to_retain": false
          },
          {
            "path": [
              "$['eu.europa.ec.eudiw.pid.1']['birth_country']"
            ],
            "intent_to_retain": false
          },
          {
            "path": [
              "$['eu.europa.ec.eudiw.pid.1']['birth_state']"
            ],
            "intent_to_retain": false
          },
          {
            "path": [
              "$['eu.europa.ec.eudiw.pid.1']['birth_city']"
            ],
            "intent_to_retain": false
          },
          {
            "path": [
              "$['eu.europa.ec.eudiw.pid.1']['resident_address']"
            ],
            "intent_to_retain": false
          },
          {
            "path": [
              "$['eu.europa.ec.eudiw.pid.1']['resident_country']"
            ],
            "intent_to_retain": false
          },
          {
            "path": [
              "$['eu.europa.ec.eudiw.pid.1']['resident_state']"
            ],
            "intent_to_retain": false
          },
          {
            "path": [
              "$['eu.europa.ec.eudiw.pid.1']['resident_city']"
            ],
            "intent_to_retain": false
          },
          {
            "path": [
              "$['eu.europa.ec.eudiw.pid.1']['resident_postal_code']"
            ],
            "intent_to_retain": false
          },
          {
            "path": [
              "$['eu.europa.ec.eudiw.pid.1']['resident_street']"
            ],
            "intent_to_retain": false
          },
          {
            "path": [
              "$['eu.europa.ec.eudiw.pid.1']['resident_house_number']"
            ],
            "intent_to_retain": false
          },
          {
            "path": [
              "$['eu.europa.ec.eudiw.pid.1']['gender']"
            ],
            "intent_to_retain": false
          },
          {
            "path": [
              "$['eu.europa.ec.eudiw.pid.1']['nationality']"
            ],
            "intent_to_retain": false
          },
          {
            "path": [
              "$['eu.europa.ec.eudiw.pid.1']['issuance_date']"
            ],
            "intent_to_retain": false
          },
          {
            "path": [
              "$['eu.europa.ec.eudiw.pid.1']['expiry_date']"
            ],
            "intent_to_retain": false
          },
          {
            "path": [
              "$['eu.europa.ec.eudiw.pid.1']['issuing_authority']"
            ],
            "intent_to_retain": false
          },
          {
            "path": [
              "$['eu.europa.ec.eudiw.pid.1']['document_number']"
            ],
            "intent_to_retain": false
          },
          {
            "path": [
              "$['eu.europa.ec.eudiw.pid.1']['administrative_number']"
            ],
            "intent_to_retain": false
          },
          {
            "path": [
              "$['eu.europa.ec.eudiw.pid.1']['issuing_country']"
            ],
            "intent_to_retain": false
          },
          {
            "path": [
              "$['eu.europa.ec.eudiw.pid.1']['issuing_jurisdiction']"
            ],
            "intent_to_retain": false
          }
        ]
      }
    }
  ]
}
""".trimIndent()
