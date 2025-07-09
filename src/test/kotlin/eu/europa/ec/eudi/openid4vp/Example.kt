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

import com.nimbusds.jose.*
import com.nimbusds.jose.crypto.ECDSASigner
import com.nimbusds.jose.jwk.Curve
import com.nimbusds.jose.jwk.ECKey
import com.nimbusds.jose.jwk.RSAKey
import com.nimbusds.jose.util.Base64URL
import com.nimbusds.jwt.JWTClaimsSet
import com.nimbusds.jwt.SignedJWT
import com.nimbusds.openid.connect.sdk.Nonce
import com.nimbusds.openid.connect.sdk.claims.IDTokenClaimsSet
import eu.europa.ec.eudi.openid4vp.SupportedClientIdScheme.Preregistered
import eu.europa.ec.eudi.openid4vp.SupportedClientIdScheme.X509SanDns
import eu.europa.ec.eudi.openid4vp.dcql.metaSdJwtVc
import eu.europa.ec.eudi.openid4vp.internal.base64UrlNoPadding
import eu.europa.ec.eudi.openid4vp.internal.jsonSupport
import eu.europa.ec.eudi.prex.*
import io.ktor.client.*
import io.ktor.client.call.*
import io.ktor.client.request.*
import io.ktor.http.*
import kotlinx.coroutines.*
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.*
import java.net.URI
import java.net.URL
import java.net.URLEncoder
import java.security.MessageDigest
import java.security.cert.X509Certificate
import java.time.Clock
import java.util.*
import eu.europa.ec.eudi.openid4vp.dcql.DCQL as DCQLQuery

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
    runUseCase(Transaction.MsoMdocPidPresentationExchange)
    runUseCase(Transaction.MsoMdocPidDcql)
    runUseCase(Transaction.SdJwtVcPidPresentationExchange)
    runUseCase(Transaction.SdJwtVcPidDcql)
    runUseCase(Transaction.SdJwtVcEhicDcql)
}

@Serializable
data class WalletResponse(
    @SerialName("id_token") val idToken: String? = null,
    @SerialName("vp_token") val vpToken: JsonElement? = null,
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
                            ifOpenId4VP = { presentationQuery, transactionData ->
                                initOpenId4VpTransaction(client, verifierApi, nonce, presentationQuery, transactionData)
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
            verifierPrintln("Placing to verifier endpoint SIOP authentication request ...")
            val request = buildJsonObject {
                put("type", "id_token")
                put("nonce", nonce)
                put("id_token_type", "subject_signed_id_token")
                put("response_mode", "direct_post.jwt")
                put("jar_mode", "by_reference")
                put("wallet_response_redirect_uri_template", "https://foo?response_code={RESPONSE_CODE}")
                put("request_uri_method", "post")
            }
            return initTransaction(client, verifierApi, request)
        }

        private suspend fun initOpenId4VpTransaction(
            client: HttpClient,
            verifierApi: URL,
            nonce: String,
            presentationQuery: Transaction.PresentationQuery,
            transactionData: List<TransactionData>?,
        ): JsonObject {
            verifierPrintln("Placing to verifier endpoint OpenId4Vp authorization request  ...")
            val request = buildJsonObject {
                put("type", "vp_token")
                put("nonce", nonce)
                when (presentationQuery) {
                    is Transaction.PresentationQuery.PresentationExchange ->
                        put("presentation_definition", jsonSupport.encodeToJsonElement(presentationQuery.presentationDefinition))
                    is Transaction.PresentationQuery.DCQL ->
                        put("dcql_query", jsonSupport.encodeToJsonElement(presentationQuery.query))
                }
                put("response_mode", "direct_post.jwt")
                put("presentation_definition_mode", "by_reference")
                put("jar_mode", "by_reference")
                put("wallet_response_redirect_uri_template", "https://foo?response_code={RESPONSE_CODE}")
                if (!transactionData.isNullOrEmpty()) {
                    putJsonArray("transaction_data") {
                        addAll(transactionData.map { it.json })
                    }
                }
                put("request_uri_method", "post")
            }
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
            val requestUri = buildString {
                iniTransactionResponse["request_uri"]?.jsonPrimitive?.contentOrNull?.encode()?.let { append("request_uri=$it") }
                iniTransactionResponse["request_uri_method"]?.jsonPrimitive?.contentOrNull?.let {
                    if (isNotBlank()) {
                        append("&")
                        append("request_uri_method=$it")
                    }
                }
            }.takeIf { it.isNotBlank() }

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
        data class PresentationExchange(val presentationDefinition: PresentationDefinition) : PresentationQuery
        data class DCQL(val query: DCQLQuery) : PresentationQuery
    }

    data object SIOP : Transaction
    data class OpenId4VP(
        val presentationQuery: PresentationQuery,
        val transactionData: List<TransactionData>? = null,
    ) : Transaction {
        init {
            transactionData?.let {
                require(it.isNotEmpty()) { "transactionData must not be empty if provided" }
            }
        }
    }

    companion object {
        val MsoMdocPidPresentationExchange = OpenId4VP(
            PresentationQuery.PresentationExchange(
                jsonSupport.decodeFromString(loadResource("/example/mso_mdoc-pid-presentation-definition.json")),
            ),
        )

        val MsoMdocPidDcql = OpenId4VP(
            PresentationQuery.DCQL(
                jsonSupport.decodeFromString(loadResource("/example/mso_mdoc-pid-dcql-query.json")),
            ),
        )

        val SdJwtVcPidPresentationExchange = run {
            val presentationDefinition = jsonSupport.decodeFromString<PresentationDefinition>(
                loadResource("/example/sd-jwt-vc-pid-presentation-definition.json"),
            )
            val inputDescriptorId = presentationDefinition.inputDescriptors.first().id
            val transactionData = TransactionData(
                TransactionDataType("eu.europa.ec.eudi.family-name-presentation"),
                listOf(TransactionDataCredentialId(inputDescriptorId.value)),
            ) {
                put("purpose", "We must verify your Family Name")
            }

            OpenId4VP(PresentationQuery.PresentationExchange(presentationDefinition), listOf(transactionData))
        }

        val SdJwtVcPidDcql = run {
            val dcql = jsonSupport.decodeFromString<DCQLQuery>(loadResource("/example/sd-jwt-vc-pid-dcql-query.json"))
            val queryId = dcql.credentials.first().id
            val transactionData = TransactionData(
                TransactionDataType("eu.europa.ec.eudi.family-name-presentation"),
                listOf(TransactionDataCredentialId(queryId.value)),
            ) {
                put("purpose", "We must verify your Family Name")
            }

            OpenId4VP(PresentationQuery.DCQL(dcql), listOf(transactionData))
        }

        val SdJwtVcEhicDcql = run {
            val dcql = jsonSupport.decodeFromString<DCQLQuery>(loadResource("/example/sd-jwt-vc-ehic-dcql-query.json"))
            OpenId4VP(PresentationQuery.DCQL(dcql))
        }
    }
}

suspend fun <T> Transaction.fold(
    ifSiop: suspend () -> T,
    ifOpenId4VP: suspend (Transaction.PresentationQuery, List<TransactionData>?) -> T,
): T = when (this) {
    Transaction.SIOP -> ifSiop()
    is Transaction.OpenId4VP -> ifOpenId4VP(presentationQuery, transactionData)
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
        return when (val presentationQuery = request.presentationQuery) {
            is PresentationQuery.ByPresentationDefinition -> {
                val presentationDefinition = presentationQuery.value
                check(1 == presentationDefinition.inputDescriptors.size) { "found more than 1 input descriptors" }
                val inputDescriptor = presentationDefinition.inputDescriptors.first()
                val requestedFormats =
                    checkNotNull(
                        inputDescriptor.format?.jsonObject()?.keys
                            ?: presentationDefinition.format?.jsonObject()?.keys,
                    ) { "formats not defined" }
                check(1 == requestedFormats.size) { "found more than 1 formats" }

                val format = requestedFormats.first()
                val verifiablePresentation = when (format) {
                    "mso_mdoc" -> VerifiablePresentation.Generic(loadResource("/example/mso_mdoc_pid-deviceresponse.txt"))
                    "vc+sd-jwt" -> prepareSdJwtVcVerifiablePresentation(request.client, request.nonce, request.transactionData)
                    else -> error("unsupported format $format")
                }

                Consensus.PositiveConsensus.VPTokenConsensus(
                    vpContent = VpContent.PresentationExchange(
                        verifiablePresentations = listOf(verifiablePresentation),
                        presentationSubmission = PresentationSubmission(
                            id = Id(UUID.randomUUID().toString()),
                            definitionId = presentationDefinition.id,
                            listOf(
                                DescriptorMap(
                                    id = inputDescriptor.id,
                                    format = format,
                                    path = JsonPath.jsonPath("$")!!,
                                ),
                            ),
                        ),
                    ),
                )
            }

            is PresentationQuery.ByDigitalCredentialsQuery -> {
                val query = presentationQuery.value
                check(1 == query.credentials.size) { "found more than 1 credentials" }
                val credential = query.credentials.first()
                val verifiablePresentation = when (val format = credential.format.value) {
                    "mso_mdoc" -> VerifiablePresentation.Generic(loadResource("/example/mso_mdoc_pid-deviceresponse.txt"))
                    "vc+sd-jwt", "dc+sd-jwt" -> {
                        val vct = credential.metaSdJwtVc?.vctValues?.firstOrNull() ?: error("no vct found")
                        prepareSdJwtVcVerifiablePresentation(
                            request.client,
                            request.nonce,
                            request.transactionData,
                            vct = vct,
                        )
                    }

                    else -> error("unsupported format $format")
                }

                Consensus.PositiveConsensus.VPTokenConsensus(
                    vpContent = VpContent.DCQL(
                        verifiablePresentations = mapOf(
                            credential.id to verifiablePresentation,
                        ),
                    ),
                )
            }
        }
    }

    private fun prepareSdJwtVcVerifiablePresentation(
        audience: Client,
        nonce: String,
        transactionData: List<TransactionData>?,
        vct: String? = null,
    ): VerifiablePresentation.Generic {
        val (sdJwtVc, holderKey) = when (vct) {
            "urn:eudi:ehic:1" ->
                loadResource("/example/sd-jwt-vc-ehic.txt") to ECKey.parse(loadResource("/example/sd-jwt-vc-ehic-key.json"))
            else ->
                loadResource("/example/sd-jwt-vc-pid.txt") to ECKey.parse(loadResource("/example/sd-jwt-vc-pid-key.json"))
        }
        check(holderKey.isPrivate) { "a private key is required" }

        val sdHash = run {
            val digest = when (vct) {
                "urn:eudi:ehic:1" -> MessageDigest.getInstance("SHA-256")
                else -> MessageDigest.getInstance("SHA3-256")
            }
            digest.update(sdJwtVc.encodeToByteArray())
            base64UrlNoPadding.encode(digest.digest())
        }
        val keyBindingJwt = run {
            val header = JWSHeader.Builder(JWSAlgorithm.ES256)
                .type(JOSEObjectType("kb+jwt"))
                .keyID(holderKey.keyID)
                .build()
            val claims = JWTClaimsSet.Builder()
                .audience(audience.id.clientId)
                .claim("nonce", nonce)
                .issueTime(Date.from(walletConfig.clock.instant()))
                .claim("sd_hash", sdHash)
                .apply {
                    if (!transactionData.isNullOrEmpty()) {
                        check(transactionData.all { HashAlgorithm.SHA_256 in it.hashAlgorithms })

                        val transactionDataHashes = transactionData.map {
                            val digest = MessageDigest.getInstance("SHA-256")
                            digest.update(it.value.encodeToByteArray())
                            base64UrlNoPadding.encode(digest.digest())
                        }

                        claim("transaction_data_hashes_alg", HashAlgorithm.SHA_256.name)
                        claim("transaction_data_hashes", transactionDataHashes)
                    }
                }
                .build()
            SignedJWT(header, claims).apply { sign(ECDSASigner(holderKey)) }
        }
        return VerifiablePresentation.Generic("$sdJwtVc${keyBindingJwt.serialize()}")
    }

    companion object {
        fun walletPrintln(s: String) = println("Wallet   : $s")
    }
}

private val TrustAnyX509: (List<X509Certificate>) -> Boolean = { _ ->
    println("Warning!! Trusting any certificate. Do not use in production")
    true
}

private fun walletConfig(vararg supportedClientIdScheme: SupportedClientIdScheme) =
    SiopOpenId4VPConfig(
        vpConfiguration = VPConfiguration(
            vpFormats = VpFormats(VpFormat.SdJwtVc.ES256, VpFormat.MsoMdoc.ES256),
            supportedTransactionDataTypes = listOf(
                SupportedTransactionDataType(
                    TransactionDataType("eu.europa.ec.eudi.family-name-presentation"),
                    setOf(HashAlgorithm.SHA_256),
                ),
            ),
        ),
        jarConfiguration = JarConfiguration(
            supportedAlgorithms = JWSAlgorithm.Family.EC.toList() - JWSAlgorithm.ES256K,
            supportedRequestUriMethods = SupportedRequestUriMethods.Both(
                SupportedRequestUriMethods.Post(
                    jarEncryption = EncryptionRequirement.Required(
                        supportedEncryptionAlgorithms = EncryptionRequirement.Required.SUPPORTED_ENCRYPTION_ALGORITHMS,
                        supportedEncryptionMethods = EncryptionRequirement.Required.SUPPORTED_ENCRYPTION_METHODS,
                        ephemeralEncryptionKeyCurve = Curve.P_521,
                    ),
                ),
            ),
        ),
        jarmConfiguration = JarmConfiguration.Encryption(
            supportedAlgorithms = listOf(JWEAlgorithm.ECDH_ES),
            supportedMethods = listOf(EncryptionMethod.A128CBC_HS256, EncryptionMethod.A256GCM),
        ),
        supportedClientIdSchemes = supportedClientIdScheme,
        clock = Clock.systemDefaultZone(),
    )

private object Resource

private fun loadResource(resource: String): String =
    Resource.javaClass.getResource(resource)
        ?.readText()
        ?: error("resource '$resource' not found")
