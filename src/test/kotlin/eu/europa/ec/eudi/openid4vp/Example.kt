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
import com.nimbusds.jose.util.Base64URL
import com.nimbusds.openid.connect.sdk.Nonce
import com.nimbusds.openid.connect.sdk.claims.IDTokenClaimsSet
import eu.europa.ec.eudi.openid4vp.SupportedClientIdScheme.Preregistered
import eu.europa.ec.eudi.openid4vp.SupportedClientIdScheme.X509SanDns
import eu.europa.ec.eudi.openid4vp.dcql.QueryId
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
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.contentOrNull
import kotlinx.serialization.json.jsonPrimitive
import java.net.URI
import java.net.URL
import java.net.URLEncoder
import java.security.SecureRandom
import java.security.cert.X509Certificate
import java.time.Clock
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
    runUseCase(Transaction.PregExPidRequest)
    runUseCase(Transaction.DcqlPidRequest)
}

@Serializable
data class WalletResponse(
    @SerialName("id_token") val idToken: String? = null,
    @SerialName("vp_token") val vpToken: JsonArray? = null,
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
                            ifOpenId4VP = { presentationQuery ->
                                initOpenId4VpTransaction(client, verifierApi, nonce, presentationQuery)
                            },
                        )
                        val presentationId = initTransactionResponse["transaction_id"]!!.jsonPrimitive.content
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
            presentationQuery: Transaction.PresentationQuery,
        ): JsonObject {
            verifierPrintln("Placing to verifier endpoint OpenId4Vp authorization request  ...")

            val (key, value) = when (presentationQuery) {
                is Transaction.PresentationQuery.PresentationExchange ->
                    "presentation_definition" to presentationQuery.presentationDefinition
                is Transaction.PresentationQuery.DCQL -> "dcql_query" to presentationQuery.query
            }
            val request =
                """
                    {
                        "type": "vp_token",
                        "nonce": "$nonce",
                        "$key": $value,
                        "response_mode": "direct_post.jwt",
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

    sealed interface PresentationQuery {
        data class PresentationExchange(val presentationDefinition: String) : PresentationQuery
        data class DCQL(val query: String) : PresentationQuery
    }

    data object SIOP : Transaction
    data class OpenId4VP(val presentationQuery: PresentationQuery) : Transaction

    companion object {
        val PregExPidRequest = OpenId4VP(PresentationQuery.PresentationExchange(PidPresentationDefinition))
        val DcqlPidRequest = OpenId4VP(PresentationQuery.DCQL(DcqlQuery))
    }
}

suspend fun <T> Transaction.fold(
    ifSiop: suspend () -> T,
    ifOpenId4VP: suspend (Transaction.PresentationQuery) -> T,
): T = when (this) {
    Transaction.SIOP -> ifSiop()
    is Transaction.OpenId4VP -> ifOpenId4VP(presentationQuery)
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
                dispatch(requestObject, consensus, EncryptionParameters.DiffieHellman(Base64URL.encode("dummy_apu")))
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
        return when (request.presentationQuery) {
            is PresentationQuery.ByPresentationDefinition -> {
                Consensus.PositiveConsensus.VPTokenConsensus(
                    vpContent = VpContent.PresentationExchange(
                        verifiablePresentations = listOf(VerifiablePresentation.Generic(DeviceResponse)),
                        presentationSubmission = PresentationSubmission(
                            id = Id("028b39fd-33b6-46a1-8887-2ef654771d7f"),
                            definitionId = Id("c64dd05a-b8b4-42dd-892e-7bb49ee06069"),
                            listOf(
                                DescriptorMap(
                                    id = InputDescriptorId("eu.europa.ec.eudi.pid.1"),
                                    format = "mso_mdoc",
                                    path = JsonPath.jsonPath("$")!!,
                                ),
                            ),
                        ),
                    ),
                )
            }
            is PresentationQuery.ByDigitalCredentialsQuery -> {
                Consensus.PositiveConsensus.VPTokenConsensus(
                    vpContent = VpContent.DCQL(
                        verifiablePresentations = mapOf(
                            QueryId("eu_europa_ec_eudi_pid_1") to VerifiablePresentation.Generic(DeviceResponse),
                        ),
                    ),
                )
            }
        }
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
        vpConfiguration = VPConfiguration(vpFormats = VpFormats(VpFormat.MsoMdoc)),
        jarmConfiguration = JarmConfiguration.Encryption(
            supportedAlgorithms = listOf(JWEAlgorithm.ECDH_ES),
            supportedMethods = listOf(EncryptionMethod.A128CBC_HS256, EncryptionMethod.A256GCM),
        ),
        supportedClientIdSchemes = supportedClientIdScheme,
        clock = Clock.systemDefaultZone(),
    )

private val PidPresentationDefinition = """
{
    "id": "c64dd05a-b8b4-42dd-892e-7bb49ee06069",
    "input_descriptors": [
        {
            "id": "eu.europa.ec.eudi.pid.1",
            "name": "Person Identification Data (PID)",
            "purpose": "",
            "format": {
                "mso_mdoc": {
                    "alg": [
                        "ES256",
                        "ES384",
                        "ES512"
                    ]
                }
            },
            "constraints": {
                "fields": [
                    {
                        "path": [
                            "$['eu.europa.ec.eudi.pid.1']['family_name']"
                        ],
                        "intent_to_retain": false
                    }
                ]
            }
        }
    ]
}
""".trimIndent()

// DeviceResponse that contains a PID and mDL
private const val DeviceResponse =
    "o2d2ZXJzaW9uYzEuMGlkb2N1bWVudHOCo2dkb2NUeXBld2V1LmV1cm9wYS5l" +
        "Yy5ldWRpLnBpZC4xbGlzc3VlclNpZ25lZKJqbmFtZVNwYWNlc6F3ZXUuZXVy" +
        "b3BhLmVjLmV1ZGkucGlkLjGB2BhYU6RoZGlnZXN0SUQBZnJhbmRvbVDLOKt7" +
        "d-Qv5sfsfZLl6ZY_cWVsZW1lbnRJZGVudGlmaWVya2ZhbWlseV9uYW1lbGVs" +
        "ZW1lbnRWYWx1ZWROZWFsamlzc3VlckF1dGiEQ6EBJqEYIVkDMTCCAy0wggKy" +
        "oAMCAQICFC_LOU7Ot-ZOjoa0RTJbEkQEmKOmMAoGCCqGSM49BAMCMFwxHjAc" +
        "BgNVBAMMFVBJRCBJc3N1ZXIgQ0EgLSBVVCAwMTEtMCsGA1UECgwkRVVESSBX" +
        "YWxsZXQgUmVmZXJlbmNlIEltcGxlbWVudGF0aW9uMQswCQYDVQQGEwJVVDAe" +
        "Fw0yNDExMjkxMTI4MzVaFw0yNjExMjkxMTI4MzRaMGkxHTAbBgNVBAMMFEVV" +
        "REkgUmVtb3RlIFZlcmlmaWVyMQwwCgYDVQQFEwMwMDExLTArBgNVBAoMJEVV" +
        "REkgV2FsbGV0IFJlZmVyZW5jZSBJbXBsZW1lbnRhdGlvbjELMAkGA1UEBhMC" +
        "VVQwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAQFmvVGq-6D9WWxhW7BQOIN" +
        "9T8zRmXMIdr0ezwpJNGIgC-HIa7JYPXI9ZAcp8mYu52a2IDzie8dGrURXZMX" +
        "147Qo4IBQzCCAT8wDAYDVR0TAQH_BAIwADAfBgNVHSMEGDAWgBSzbLiRFxzX" +
        "pBpmMYdC4YvAQMyVGzAnBgNVHREEIDAeghxkZXYuaXNzdWVyLWJhY2tlbmQu" +
        "ZXVkaXcuZGV2MBIGA1UdJQQLMAkGByiBjF0FAQYwQwYDVR0fBDwwOjA4oDag" +
        "NIYyaHR0cHM6Ly9wcmVwcm9kLnBraS5ldWRpdy5kZXYvY3JsL3BpZF9DQV9V" +
        "VF8wMS5jcmwwHQYDVR0OBBYEFPHhwPzF75MgheENYqLlz9LKYjFIMA4GA1Ud" +
        "DwEB_wQEAwIHgDBdBgNVHRIEVjBUhlJodHRwczovL2dpdGh1Yi5jb20vZXUt" +
        "ZGlnaXRhbC1pZGVudGl0eS13YWxsZXQvYXJjaGl0ZWN0dXJlLWFuZC1yZWZl" +
        "cmVuY2UtZnJhbWV3b3JrMAoGCCqGSM49BAMCA2kAMGYCMQCYykgNwO5GDgWM" +
        "CQjjnK3GkQg3lU33L2GAkfAI8p1ItuSP7ZLAwhQOfpmgi35pFCkCMQDlYxrI" +
        "JbkMEzedKPe1popR25VuDfPqgK5rAQvI0yLrZyn3OMmd7uUNbmWCJW7Skq5Z" +
        "BM_YGFkEyqZndmVyc2lvbmMxLjBvZGlnZXN0QWxnb3JpdGhtZ1NIQS0yNTZs" +
        "dmFsdWVEaWdlc3RzoXdldS5ldXJvcGEuZWMuZXVkaS5waWQuMbgZAFggOhcW" +
        "Gq5FFshUpShyf_v7d8LYVx6hQCdnxqhpPYHXptEBWCBhxi-7MIUyIEf9eXsm" +
        "tpb6bS3WMlvb1IKVfJDGL-E3cAJYICXP8ZyU3U_4e51NAohWDbqmeGabjj93" +
        "_FA6Q7_KxPKwA1ggHEMoLXvCT6RW1CVMeMU47-rwRMj7wVjbJ0_UBQ_sZ-wE" +
        "WCDT9-SwKjha0nna10diAO9IxPB46svGBKkNiXAR77IdyAVYIMjjf2tii5oc" +
        "W3XHKUmvtaIje4jpQz0AuL7Twe33abktBlggKhhf9sCpvmndwAAKW4umOxWk" +
        "Ltz4Kyv1h5zcAEwNUvAHWCDp6NsFQJmpb9Jatz_dBayRv14x2Qffl4AxCOzR" +
        "ouFWsQhYIEOC_EaY5ww8qW60NZ_cYfn40xgFSZKjxzReZuqxWMx8CVggHuln" +
        "1oLn-ZOufRheOmtSHxAxl4acTxZ52w2_QbUYiFgKWCB9i5tS8oKFUb55BroS" +
        "RVPs1siu1VH5XVV-kt1vUGlhAAtYIB0ta7Hoc4HGgDVL-cLCo7wJ-fOzaXTs" +
        "faLc5V56a0GsDFggHSDNQdsvGKwx4pvXJ9zVcwlbUds_6uSwNKiRqBa-QgEN" +
        "WCCA18f0ek8765otJdOkDu-NhvxuKVaRG9YZKPpjARSyWA5YIOzd-VzaPIJP" +
        "nJTEgkl13Wx8vaZ0JN2roUyyXxQJ19dBD1ggo7HAuf1bjEPAvB_QsPoNGk82" +
        "qUxifiYfc-clTFQGjs4QWCCV9sgpz0Pwiu9tGxApqWyDc1LtD_Fu5AZ4Gk4A" +
        "l0TQDhFYIBirH7jbqqpXrh4r0kzLEeut0u8wkIpanFk0TzliVmwnElggTpMB" +
        "OhEWHDOMUXV2DTBDYtUIcO5j94bZAxZIFfWNsGMTWCCtRqkcGgnf-L4qexXf" +
        "_bS2I32qfG_tCTUaSSjLBkQibxRYIPrvcdGkjj7uH31FoWjM4aoo7mCwH6TD" +
        "2FklUg-GfRbtFVgglAIC8TTTc6JW5azcNzrm3DTujvKvb1fT2bOfMnC0ZasW" +
        "WCAn1cdYJ8UFyYHiG5ZhdJkntNNrtS5ZVSdLfqKZo866QBdYIP3SPKdiReOR" +
        "5XVI3mP-JIekpQQTFHVCJmhMr8JAuFhcGBhYIIz9kkhORpqu7260xaPkzHBm" +
        "-T92zcYOcWA0yjGhYU3JbWRldmljZUtleUluZm-haWRldmljZUtleaQBAiAB" +
        "IVggJ0AUWqVTHQCZLfZ9l6etiocOFUDMiwOA9NdRMlnEdNUiWCDQqWiJYDFx" +
        "5WrF3iWOF_eyDwMlb2lwwbr8vJH9QsEtpmdkb2NUeXBld2V1LmV1cm9wYS5l" +
        "Yy5ldWRpLnBpZC4xbHZhbGlkaXR5SW5mb6Nmc2lnbmVkwHgeMjAyNS0wMi0w" +
        "N1QxNDoxNDoxNC4yNTQxMzU5MzRaaXZhbGlkRnJvbcB4HjIwMjUtMDItMDdU" +
        "MTQ6MTQ6MTQuMjU0MTM1OTM0Wmp2YWxpZFVudGlswHgeMjAyNy0wMi0wN1Qx" +
        "NDoxNDoxNC4yNTQxMzU5MzRaWEDTbHm2IyQEZlx3sywuYiw3qICbikVdUtya" +
        "HceDdV4qIAQdpOScsTAWTH9GVvh1FiPWE2qdQCTdl8O9_wGQpth3bGRldmlj" +
        "ZVNpZ25lZKJqbmFtZVNwYWNlc9gYQaBqZGV2aWNlQXV0aKFvZGV2aWNlU2ln" +
        "bmF0dXJlhEOhASag9lhA0Cu_ymkje1B5BkBExIvyYCaFQqItzzaB8Mr1UPkS" +
        "j86gWYjvKRhwmPKDEP0BoxZbwDqdmP0z1Q5BFGfIHLFqaqNnZG9jVHlwZXVv" +
        "cmcuaXNvLjE4MDEzLjUuMS5tRExsaXNzdWVyU2lnbmVkompuYW1lU3BhY2Vz" +
        "oXFvcmcuaXNvLjE4MDEzLjUuMYHYGFhXpGhkaWdlc3RJRABmcmFuZG9tUG79" +
        "RwEsn9sSFymhhWnyeqZxZWxlbWVudElkZW50aWZpZXJrZmFtaWx5X25hbWVs" +
        "ZWxlbWVudFZhbHVlaEdlb3JnaW91amlzc3VlckF1dGiEQ6EBJqEYIVkDMTCC" +
        "Ay0wggKyoAMCAQICFC_LOU7Ot-ZOjoa0RTJbEkQEmKOmMAoGCCqGSM49BAMC" +
        "MFwxHjAcBgNVBAMMFVBJRCBJc3N1ZXIgQ0EgLSBVVCAwMTEtMCsGA1UECgwk" +
        "RVVESSBXYWxsZXQgUmVmZXJlbmNlIEltcGxlbWVudGF0aW9uMQswCQYDVQQG" +
        "EwJVVDAeFw0yNDExMjkxMTI4MzVaFw0yNjExMjkxMTI4MzRaMGkxHTAbBgNV" +
        "BAMMFEVVREkgUmVtb3RlIFZlcmlmaWVyMQwwCgYDVQQFEwMwMDExLTArBgNV" +
        "BAoMJEVVREkgV2FsbGV0IFJlZmVyZW5jZSBJbXBsZW1lbnRhdGlvbjELMAkG" +
        "A1UEBhMCVVQwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAQFmvVGq-6D9WWx" +
        "hW7BQOIN9T8zRmXMIdr0ezwpJNGIgC-HIa7JYPXI9ZAcp8mYu52a2IDzie8d" +
        "GrURXZMX147Qo4IBQzCCAT8wDAYDVR0TAQH_BAIwADAfBgNVHSMEGDAWgBSz" +
        "bLiRFxzXpBpmMYdC4YvAQMyVGzAnBgNVHREEIDAeghxkZXYuaXNzdWVyLWJh" +
        "Y2tlbmQuZXVkaXcuZGV2MBIGA1UdJQQLMAkGByiBjF0FAQYwQwYDVR0fBDww" +
        "OjA4oDagNIYyaHR0cHM6Ly9wcmVwcm9kLnBraS5ldWRpdy5kZXYvY3JsL3Bp" +
        "ZF9DQV9VVF8wMS5jcmwwHQYDVR0OBBYEFPHhwPzF75MgheENYqLlz9LKYjFI" +
        "MA4GA1UdDwEB_wQEAwIHgDBdBgNVHRIEVjBUhlJodHRwczovL2dpdGh1Yi5j" +
        "b20vZXUtZGlnaXRhbC1pZGVudGl0eS13YWxsZXQvYXJjaGl0ZWN0dXJlLWFu" +
        "ZC1yZWZlcmVuY2UtZnJhbWV3b3JrMAoGCCqGSM49BAMCA2kAMGYCMQCYykgN" +
        "wO5GDgWMCQjjnK3GkQg3lU33L2GAkfAI8p1ItuSP7ZLAwhQOfpmgi35pFCkC" +
        "MQDlYxrIJbkMEzedKPe1popR25VuDfPqgK5rAQvI0yLrZyn3OMmd7uUNbmWC" +
        "JW7Skq5ZBOvYGFkE5qZndmVyc2lvbmMxLjBvZGlnZXN0QWxnb3JpdGhtZ1NI" +
        "QS0yNTZsdmFsdWVEaWdlc3RzoXFvcmcuaXNvLjE4MDEzLjUuMbgaAFggMB0u" +
        "LEYoIneUL0kereEYCwIDPhFlzG8CRz8mhaOAjqYBWCDeL02NKHTFMnNnvQhi" +
        "CvqpTol-KZsWotcrp0qQZX5d5QJYIEe49kmpXoF28fhJp_mmyvaJ9_DWptgc" +
        "iOwNDLjvGG3vA1ggwS9c7Pgo_bVTGX6_kKL6b_S_XdFpJeZrNPIzztOfIiYE" +
        "WCAewkcL6ERlKhMrKfRcIc6kk4686GEw9391vK-1DqC3OAVYICjzEaK6wNF3" +
        "xg2ihweQATbQe3NWUevjQJA6UE7qgKxBBlgg3HBSVgWY5xeur7rNraq3xyiL" +
        "9nUWMGU5aOJsSc8tspcHWCAb4P2vyc0Y5AaqLTtupspXYNYOadmK6xPBSlf9" +
        "CTB6DQhYIIi6l_O69bNVfXPwXmyTIDNGgWUCgasiNr3Py4vtd8lgCVggm_9U" +
        "faiuFMpyG5Wk25RMt_NRsRyo_hX1NR1PqzTMeeEKWCCGP-XEprUyt6azpavK" +
        "itGk-A1uv3_SrJuXqm4MAlZHvAtYIHdyYg5YZxq_Zu5g7ERaw3LytEpihtNT" +
        "_oXk2eKXsNXBDFgg_5GNWEZH0tJQ_Yd12HuMQCKg0cx2KthoMznsTj3wxeUN" +
        "WCBU8driwLnS1IB97lWGJ2J79P-tg8FjIZ5CvFIBJ6FACg5YIIIJZd7HfHi0" +
        "6lFp0IbKCcrsVz86mIt39RxTR-603zCgD1ggE20AVA9nIp5-ttQ9i6CU8UD3" +
        "U3GrH-L-FNoYSlZ_j_0QWCAy6d3Q8GMFj_I_m2KLaw-X-S4eMRBmE7O2Ou_J" +
        "_H09mxFYIGxt_8sVd3BoMRZiu-uBJovSmstMIgFXSM2FaMmXSydnElggxQJZ" +
        "bssCwVYRnv2ZdAa1eNkFdvgalLNfMEhxpTnNiIsTWCB_u8P7WHe8ll2-OxbM" +
        "2UXLxNNDPJUQaXo4438QLdSunBRYIMcUaKm2dLv44pOSZvwwTw7y1c3pRiLh" +
        "S0Or4EQp1ozIFVgg2qZd8xExSL5Ypu6JigV2F3IzdAGCqNq109RVDAHpwsUW" +
        "WCAfpZrVbcpvXhUwrXewy0LMWpWW8ZmbUiGkM8UARkKEMBdYIIRZ3sDbFWF1" +
        "31NYO2ATE3BrFJLY_2cTzk_UrJ9Vm84RGBhYIG29wGNAT-5IBorJLIin3-bg" +
        "AYOXW6G_fSa2zFh0J1zFGBlYIAummtqcnzwR_AjgluEA9xb8ClHXm7nDFArD" +
        "_uyNnpkHbWRldmljZUtleUluZm-haWRldmljZUtleaQBAiABIVgglui92Ffs" +
        "uUU1Q0Sq1ZYIrAOxLzzPS4674eae1vRHoRwiWCAJJtjfLV3LGzfmoBLuCw_y" +
        "3Nv1fmCd_YRby0hzYn8Tnmdkb2NUeXBldW9yZy5pc28uMTgwMTMuNS4xLm1E" +
        "TGx2YWxpZGl0eUluZm-jZnNpZ25lZMB4HjIwMjUtMDItMDdUMTQ6MTQ6MTQu" +
        "NTgxNjk3NDM2Wml2YWxpZEZyb23AeB4yMDI1LTAyLTA3VDE0OjE0OjE0LjU4" +
        "MTY5NzQzNlpqdmFsaWRVbnRpbMB4HjIwMjctMDItMDdUMTQ6MTQ6MTQuNTgx" +
        "Njk3NDM2WlhAGmdQqmiiBzUJkYj_dUzBwGjjwWMdO_qC_MmEvP-ni6il-VTB" +
        "kJe2952j87Oa9v-a-HbfTcAKgX7w0BFb46iAs2xkZXZpY2VTaWduZWSiam5h" +
        "bWVTcGFjZXPYGEGgamRldmljZUF1dGihb2RldmljZVNpZ25hdHVyZYRDoQEm" +
        "oPZYQOsoPictwMbFLFsbHRyS7GnPn9nHYogN-xkLYjJv0DGs0YU7LhAHRpqL" +
        "GFe1ira5MD7ryABhUSUeoNth94vr3W1mc3RhdHVzAA"

private val DcqlQuery = """
{
    "credentials": [
        {
            "id": "eu_europa_ec_eudi_pid_1",
            "format": "mso_mdoc",
            "meta": {
                "doctype_value": "eu.europa.ec.eudi.pid.1"
            },
            "claims": [
                {
                    "namespace": "eu.europa.ec.eudi.pid.1",
                    "claim_name": "family_name"
                }
            ]
        }
    ]
}
""".trimIndent()
