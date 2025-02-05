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

import com.fasterxml.jackson.databind.ObjectMapper
import com.fasterxml.jackson.module.kotlin.readValue
import com.nimbusds.jose.JOSEObjectType
import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.JWSHeader
import com.nimbusds.jose.crypto.factories.DefaultJWSSignerFactory
import com.nimbusds.jose.jwk.JWKMatcher
import com.nimbusds.jose.jwk.JWKSet
import com.nimbusds.jose.jwk.KeyType
import com.nimbusds.jose.jwk.KeyUse
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator
import com.nimbusds.jwt.JWTClaimsSet
import com.nimbusds.jwt.SignedJWT
import com.nimbusds.oauth2.sdk.id.State
import eu.europa.ec.eudi.openid4vp.internal.base64UrlNoPadding
import eu.europa.ec.eudi.openid4vp.internal.request.DefaultAuthorizationRequestResolver
import eu.europa.ec.eudi.openid4vp.internal.request.UnvalidatedClientMetaData
import eu.europa.ec.eudi.prex.PresentationDefinition
import eu.europa.ec.eudi.prex.PresentationExchange
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.test.runTest
import kotlinx.serialization.ExperimentalSerializationApi
import kotlinx.serialization.SerializationException
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.*
import org.apache.http.NameValuePair
import org.apache.http.client.utils.URIBuilder
import org.apache.http.message.BasicNameValuePair
import org.junit.jupiter.api.DisplayName
import org.junit.jupiter.api.Nested
import java.io.InputStream
import java.net.URLEncoder
import java.security.KeyStore
import java.security.cert.X509Certificate
import java.time.Clock
import java.util.*
import kotlin.test.*

class UnvalidatedRequestResolverTest {

    private val json: Json by lazy { Json { ignoreUnknownKeys = true } }

    private val pd = readFileAsText("presentation-definition/basic_example.json")
        .replace("\r\n", "")
        .replace("\r", "")
        .replace("\n", "")
        .replace("  ", "")
        .also { URLEncoder.encode(it, "UTF-8") }

    private val dcqlQuery = readFileAsText("dcql/basic_example.json")
        .replace("\r\n", "")
        .replace("\r", "")
        .replace("\n", "")
        .replace("  ", "")
        .also { URLEncoder.encode(it, "UTF-8") }

    private val signingKey = RSAKeyGenerator(2048)
        .keyUse(KeyUse.SIGNATURE) // indicate the intended use of the key (optional)
        .keyID(UUID.randomUUID().toString()) // give the key a unique ID (optional)
        .issueTime(Date(System.currentTimeMillis())) // issued-at timestamp (optional)
        .generate()

    private val jwkSetJO = Json.parseToJsonElement(
        """ { 
                "keys": [ {
                      "kty": "RSA",
                      "e": "AQAB",
                      "use": "sig",
                      "kid": "a0779cde-0615-41b3-89b7-aec75faa159d",
                      "iat": 1701436001,
                      "n": "k4gz8H4Rvuh7ShPHpOwSPN9SWWBUxApgOuBYzDQOa4rXMmUs20egROvtDQYf2C0o-mZEPUXNq8-I79v9j_Uacum2CQWpOPd7Z-kXGZsE7Z9HAqVPqQnMNUU2aQPc8WYbkrXOrFjFIo0GQuVObVMN_1wh2k94JLFoqRAx2TLMrRu-pQUQfN1iTL-2yL3Cn-Ri3W_sxhdLV0uKdviKcU437LdvrpE3eoXePxofmDxG2udX6TSqNvzRZpKR9Vqy9hKaTppAHp_0G1fQ4dSCLpSY9hxGEuTFgFAyvtZZhZrL2OFa6XHPC60uX5-Iir2K0IymSPrVpftxNUACKebkh5FTGw"
                    } ] 
        } 
        """.trimIndent(),
    ).jsonObject

    private val walletConfig = SiopOpenId4VPConfig(
        supportedClientIdSchemes = listOf(
            SupportedClientIdScheme.Preregistered(
                PreregisteredClient(
                    clientId = "Verifier",
                    legalName = "Verifier",
                    jarConfig = JWSAlgorithm.RS256 to JwkSetSource.ByValue(
                        Json.parseToJsonElement(
                            JWKSet(signingKey).toPublicJWKSet().toString(),
                        ).jsonObject,
                    ),
                ),
            ),
            SupportedClientIdScheme.X509SanDns(::validateChain),
            SupportedClientIdScheme.X509SanUri(::validateChain),
            SupportedClientIdScheme.RedirectUri,
        ),
        jarConfiguration = JarConfiguration(
            supportedAlgorithms = listOf(JWSAlgorithm.RS256),
        ),
        vpConfiguration = VPConfiguration(
            vpFormats = VpFormats(VpFormat.MsoMdoc, VpFormat.SdJwtVc.ES256),
            supportedTransactionDataTypes = listOf(
                SupportedTransactionDataType(
                    TransactionDataType("basic-transaction-data"),
                    setOf(HashAlgorithm.SHA_256, HashAlgorithm("sha-384")),
                ),
            ),
        ),
        clock = Clock.systemDefaultZone(),
    )

    private val resolver = DefaultAuthorizationRequestResolver(walletConfig, DefaultHttpClientFactory)

    private val clientMetadataJwksInline =
        """ {
             "jwks": $jwkSetJO,              
             "subject_syntax_types_supported": [ "urn:ietf:params:oauth:jwk-thumbprint", "did:example", "did:key" ]              
            } 
        """.trimIndent().let {
            URLEncoder.encode(it, "UTF-8")
        }

    private val clientMetadataJwksInlineNoSubjectSyntaxTypes =
        """ {
             "jwks": $jwkSetJO              
            } 
        """.trimIndent().let {
            URLEncoder.encode(it, "UTF-8")
        }

    private fun genState(): String {
        return State().value
    }

    @Test
    fun `vp token auth request`() = runTest {
        suspend fun test(state: String? = null) {
            val authRequest =
                "https://client.example.org/universal-link?" +
                    "response_type=vp_token" +
                    "&client_id=redirect_uri%3Ahttps%3A%2F%2Fclient.example.org%2Fcb" +
                    "&redirect_uri=https%3A%2F%2Fclient.example.org%2Fcb" +
                    "&nonce=n-0S6_WzA2Mj" +
                    (state?.let { "&state=$it" } ?: "") +
                    "&presentation_definition=$pd" +
                    "&client_metadata=$clientMetadataJwksInlineNoSubjectSyntaxTypes"

            val resolution = resolver.resolveRequestUri(authRequest)
            resolution.validateSuccess<ResolvedRequestObject.OpenId4VPAuthorization>()
        }

        test(genState())
        test()
    }

    @Test
    fun `vp token auth request with DCQL query`() = runTest {
        suspend fun test(state: String? = null) {
            val authRequest =
                "https://client.example.org/universal-link?" +
                    "response_type=vp_token" +
                    "&client_id=redirect_uri%3Ahttps%3A%2F%2Fclient.example.org%2Fcb" +
                    "&redirect_uri=https%3A%2F%2Fclient.example.org%2Fcb" +
                    "&nonce=n-0S6_WzA2Mj" +
                    (state?.let { "&state=$it" } ?: "") +
                    "&dcql_query=$dcqlQuery" +
                    "&client_metadata=$clientMetadataJwksInlineNoSubjectSyntaxTypes"

            val resolution = resolver.resolveRequestUri(authRequest)
            resolution.validateSuccess<ResolvedRequestObject.OpenId4VPAuthorization>()
        }

        test(genState())
        test()
    }

    @Test
    fun `id token auth request`() = runTest {
        suspend fun test(state: String? = null) {
            val authRequest =
                "https://client.example.org/universal-link?" +
                    "response_type=id_token" +
                    "&client_id=redirect_uri%3Ahttps%3A%2F%2Fclient.example.org%2Fcb" +
                    "&redirect_uri=https%3A%2F%2Fclient.example.org%2Fcb" +
                    "&nonce=n-0S6_WzA2Mj" +
                    (state?.let { "&state=$it" } ?: "") +
                    "&scope=openid" +
                    "&client_metadata=$clientMetadataJwksInline"

            val resolution = resolver.resolveRequestUri(authRequest)

            resolution.validateSuccess<ResolvedRequestObject.SiopAuthentication>()
        }

        test(genState())
        test()
    }

    @Test
    fun `id and vp token auth request`() = runTest {
        suspend fun test(state: String? = null) {
            val authRequest =
                "https://client.example.org/universal-link?" +
                    "response_type=vp_token%20id_token" +
                    "&client_id=redirect_uri%3Ahttps%3A%2F%2Fclient.example.org%2Fcb" +
                    "&redirect_uri=https%3A%2F%2Fclient.example.org%2Fcb" +
                    "&nonce=n-0S6_WzA2Mj" +
                    "&scope=openid" +
                    (state?.let { "&state=$it" } ?: "") +
                    "&presentation_definition=$pd" +
                    "&client_metadata=$clientMetadataJwksInline"

            val resolution = resolver.resolveRequestUri(authRequest)

            resolution.validateSuccess<ResolvedRequestObject.SiopOpenId4VPAuthentication>()
        }

        test(genState())
        test()
    }

    @Test
    fun `if response_mode is not JARM related client_metadata are not mandatory to be provided`() = runTest {
        suspend fun test(state: String? = null) {
            val authRequest =
                "https://client.example.org/universal-link?" +
                    "response_type=vp_token" +
                    "&response_mode=direct_post" +
                    "&client_id=redirect_uri%3Ahttps%3A%2F%2Fclient.example.org%2Fcb" +
                    "&response_uri=https%3A%2F%2Fclient.example.org%2Fcb" +
                    "&nonce=n-0S6_WzA2Mj" +
                    (state?.let { "&state=$it" } ?: "") +
                    "&presentation_definition=$pd"

            val resolution = resolver.resolveRequestUri(authRequest)

            resolution.validateSuccess<ResolvedRequestObject.OpenId4VPAuthorization>()
        }

        test(genState())
        test()
    }

    @Test
    fun `JAR auth request, request passed as JWT, verified with pre-registered client scheme`() = runBlocking {
        suspend fun test(typ: JOSEObjectType? = null) {
            val jwkSet = JWKSet(signingKey)
            val unvalidatedClientMetaData = UnvalidatedClientMetaData(
                jwks = Json.parseToJsonElement(jwkSet.toPublicJWKSet().toString()).jsonObject,
                subjectSyntaxTypesSupported = listOf(
                    "urn:ietf:params:oauth:jwk-thumbprint",
                    "did:example",
                    "did:key",
                ),
            )
            val jwtClaimsSet = jwtClaimsSet(
                "Verifier",
                "https://eudi.netcompany-intrasoft.com/wallet/direct_post",
                unvalidatedClientMetaData,
            )

            val signedJwt = createSignedRequestJwt(jwkSet, jwtClaimsSet, typ)
            val authRequest =
                """
             http://localhost:8080/public_url?client_id=Verifier&request=$signedJwt
                """.trimIndent()

            val resolution = resolver.resolveRequestUri(authRequest)

            resolution.validateSuccess<ResolvedRequestObject.OpenId4VPAuthorization>()
        }

        test()
        test(JOSEObjectType(""))
        test(JOSEObjectType("oauth-authz-req+jwt"))
        test(JOSEObjectType("jwt"))
    }

    @Test
    fun `JAR auth request, request passed as JWT, verified with x509_san_dns scheme`() = runTest {
        suspend fun test(typ: JOSEObjectType? = null) {
            val keyStore = KeyStore.getInstance("JKS")
            keyStore.load(
                load("certificates/certificates.jks"),
                "12345".toCharArray(),
            )
            val clientId = "x509_san_dns:verifier.example.gr"
            val jwtClaimsSet = jwtClaimsSet(
                clientId,
                "https://verifier.example.gr/wallet/direct_post",
                UnvalidatedClientMetaData(
                    jwks = Json.parseToJsonElement(JWKSet(signingKey).toPublicJWKSet().toString()).jsonObject,
                    subjectSyntaxTypesSupported = listOf(
                        "urn:ietf:params:oauth:jwk-thumbprint",
                        "did:example",
                        "did:key",
                    ),
                ),
            )
            val signedJwt = createSignedRequestJwt(keyStore, jwtClaimsSet, typ)
            val authRequest = "http://localhost:8080/public_url?client_id=$clientId&request=$signedJwt"

            val resolution = resolver.resolveRequestUri(authRequest)
            resolution.validateSuccess<ResolvedRequestObject.OpenId4VPAuthorization>()
        }

        test()
        test(JOSEObjectType(""))
        test(JOSEObjectType("oauth-authz-req+jwt"))
        test(JOSEObjectType("jwt"))
    }

    @Test
    fun `JAR auth request, request passed as JWT, verified with x509_san_uri scheme`() = runTest {
        suspend fun test(typ: JOSEObjectType? = null) {
            val keyStore = KeyStore.getInstance("JKS")
            keyStore.load(
                load("certificates/certificates.jks"),
                "12345".toCharArray(),

            )
            val clientId = "x509_san_uri:https://verifier.example.gr"
            val clientIdEncoded = URLEncoder.encode(clientId, "UTF-8")
            val jwtClaimsSet = jwtClaimsSet(
                clientId,
                "https://verifier.example.gr",
                UnvalidatedClientMetaData(
                    jwks = Json.parseToJsonElement(JWKSet(signingKey).toPublicJWKSet().toString()).jsonObject,
                    subjectSyntaxTypesSupported = listOf(
                        "urn:ietf:params:oauth:jwk-thumbprint",
                        "did:example",
                        "did:key",
                    ),
                ),
            )
            val signedJwt = createSignedRequestJwt(keyStore, jwtClaimsSet, typ)
            val authRequest = "http://localhost:8080/public_url?client_id=$clientIdEncoded&request=$signedJwt"

            val resolution = resolver.resolveRequestUri(authRequest)
            resolution.validateSuccess<ResolvedRequestObject.OpenId4VPAuthorization>()
        }

        test()
        test(JOSEObjectType(""))
        test(JOSEObjectType("oauth-authz-req+jwt"))
        test(JOSEObjectType("jwt"))
    }

    private fun createSignedRequestJwt(
        jwkSet: JWKSet,
        jwtClaimsSet: JWTClaimsSet,
        typ: JOSEObjectType?,
    ): String {
        val headerBuilder = JWSHeader.Builder(JWSAlgorithm.RS256)
        headerBuilder.keyID(jwkSet.keys[0].keyID)
        typ?.let {
            headerBuilder.type(it)
        }

        val signedJWT = SignedJWT(headerBuilder.build(), jwtClaimsSet)

        val signer = DefaultJWSSignerFactory().createJWSSigner(jwkSet.keys[0], JWSAlgorithm.RS256)
        signedJWT.sign(signer)

        return signedJWT.serialize()
    }

    private fun createSignedRequestJwt(
        keyStore: KeyStore,
        jwtClaimsSet: JWTClaimsSet,
        typ: JOSEObjectType?,
    ): String {
        val chain = keyStore.getCertificateChain("verifierexample")
        val base64EncodedChain = chain.map {
            com.nimbusds.jose.util.Base64.encode(it.encoded)
        }
        val headerBuilder = JWSHeader.Builder(JWSAlgorithm.RS256)
        headerBuilder.x509CertChain(base64EncodedChain.toMutableList())
        typ.let {
            headerBuilder.type(it)
        }

        val signedJWT = SignedJWT(headerBuilder.build(), jwtClaimsSet)

        val jwkSet = JWKSet.load(keyStore) { _ -> "12345".toCharArray() }
        val signingKey = jwkSet.filter(
            JWKMatcher.Builder()
                .keyType(KeyType.RSA)
                .keyID("verifierexample")
                .build(),
        ).keys[0]

        val signer = DefaultJWSSignerFactory().createJWSSigner(signingKey)
        signedJWT.sign(signer)

        return signedJWT.serialize()
    }

    private fun jwtClaimsSet(
        clientId: String,
        responseUri: String,
        clientMetadata: UnvalidatedClientMetaData,
    ): JWTClaimsSet {
        val presentationDefinition =
            PresentationExchange.jsonParser.decodePresentationDefinition(load("request-object/eudi_pid_presentation_definition.json"))
                .also { println(it) }
                .fold(onSuccess = { it }, onFailure = { org.junit.jupiter.api.fail(it) })

        return with(JWTClaimsSet.Builder()) {
            audience("https://self-issued.me/v2")
            issueTime(Date())
            claim("client_id", clientId)
            claim("response_uri", responseUri)
            claim("response_type", "vp_token")
            claim("nonce", "nonce")
            claim("response_mode", "direct_post")
            claim("presentation_definition", Jackson.toJsonObject(presentationDefinition))
            claim("state", "638JwH0b2jrhGlAZQVa50KysVazkI-YpiFcLj2DLMalJpZK6XC22vAsPqXkpwAwXzfYpK-WLc3GhHYK8lbT6rw")
            claim("client_metadata", Jackson.toJsonObject(clientMetadata))
            build()
        }
    }

    @Test
    fun `response type provided comma separated`() = runTest {
        suspend fun test(state: String? = null) {
            val authRequest =
                "https://client.example.org/universal-link?" +
                    "response_type=id_token,vp_token" +
                    "&client_id=redirect_uri%3Ahttps%3A%2F%2Fclient.example.org%2Fcb" +
                    "&redirect_uri=https%3A%2F%2Fclient.example.org%2Fcb" +
                    "&nonce=n-0S6_WzA2Mj" +
                    (state?.let { "&state=$it" } ?: "") +
                    "&client_metadata=$clientMetadataJwksInline"

            val resolution = resolver.resolveRequestUri(authRequest)

            resolution.validateInvalid<RequestValidationError.UnsupportedResponseType>()
        }

        test(genState())
        test()
    }

    @Test
    fun `response type provided is miss-spelled`() = runTest {
        suspend fun test(state: String? = null) {
            val authRequest =
                "https://client.example.org/universal-link?" +
                    "response_type=id_tokens" +
                    "&client_id=redirect_uri%3Ahttps%3A%2F%2Fclient.example.org%2Fcb" +
                    "&redirect_uri=https%3A%2F%2Fclient.example.org%2Fcb" +
                    "&nonce=n-0S6_WzA2Mj" +
                    (state?.let { "&state=$it" } ?: "") +
                    "&client_metadata=$clientMetadataJwksInline"

            val resolution = resolver.resolveRequestUri(authRequest)

            resolution.validateInvalid<RequestValidationError.UnsupportedResponseType>()
        }

        test(genState())
        test()
    }

    @Test
    fun `nonce validation`() = runTest {
        suspend fun test(state: String? = null) {
            val authRequest =
                "https://client.example.org/universal-link?" +
                    "response_type=id_token" +
                    "&client_id=redirect_uri%3Ahttps%3A%2F%2Fclient.example.org%2Fcb" +
                    (state?.let { "&state=$it" } ?: "") +
                    "&redirect_uri=https%3A%2F%2Fclient.example.org%2Fcb" +
                    "&client_metadata=$clientMetadataJwksInline"

            val resolution = resolver.resolveRequestUri(authRequest)

            resolution.validateInvalid<RequestValidationError.MissingNonce>()
        }

        test(genState())
        test()
    }

    @Test
    fun `if client_id is missing reject the request`() = runTest {
        suspend fun test(state: String? = null) {
            val authRequest =
                "https://client.example.org/universal-link?" +
                    "response_type=id_token" +
                    "&redirect_uri=https%3A%2F%2Fclient.example.org%2Fcb" +
                    "&nonce=n-0S6_WzA2Mj" +
                    (state?.let { "&state=$it" } ?: "") +
                    "&client_metadata=$clientMetadataJwksInline"

            val resolution = resolver.resolveRequestUri(authRequest)

            resolution.validateInvalid<RequestValidationError.MissingClientId>()
        }

        test(genState())
        test()
    }

    @OptIn(ExperimentalSerializationApi::class)
    fun readFileAsText(fileName: String): String {
        return json.decodeFromStream<JsonObject>(load(fileName)).jsonObject.toString()
    }

    private fun validateChain(chain: List<X509Certificate>): Boolean {
        return try {
            for (i in chain.indices)
                if (i > 0) chain[i - 1].verify(chain[i].publicKey)
            true
        } catch (e: Exception) {
            false
        }
    }

    private fun load(f: String): InputStream =
        UnvalidatedRequestResolverTest::class.java.classLoader.getResourceAsStream(f) ?: error("File $f not found")

    private inline fun <reified T : ResolvedRequestObject> Resolution.validateSuccess(): T =
        when (this) {
            is Resolution.Success -> assertIs(requestObject, "${T::class} data expected")
            is Resolution.Invalid -> fail("Invalid resolution found while expected success\n$error")
        }

    private inline fun <reified T : AuthorizationRequestError> Resolution.validateInvalid(): T =
        when (this) {
            is Resolution.Invalid -> assertIs(error, "${T::class} error expected")
            else -> fail("Success resolution found while expected Invalid")
        }

    @DisplayName("when using transaction_data")
    @Nested
    inner class TransactionDataTest {

        private val presentationExchangeQuery =
            BasicNameValuePair("presentation_definition", readFileAsText("presentation-definition/basic_example.json"))
        private val dcqlQuery = BasicNameValuePair("dcql_query", readFileAsText("dcql/basic_example.json"))

        private suspend fun testAndThen(
            transactionData: JsonArray,
            query: NameValuePair = presentationExchangeQuery,
            block: suspend (Resolution) -> Unit,
        ) {
            val state = genState()
            val clientMetadata = buildJsonObject {
                put("jwks", jwkSetJO)
            }
            val authorizationUrl = URIBuilder("https://client.example.org/universal-link")
                .addParameter("response_type", "vp_token")
                .addParameter("client_id", "redirect_uri:https://client.example.org/cb")
                .addParameter("redirect_uri", "https://client.example.org/cb")
                .addParameter("nonce", "n-0S6_WzA2Mj")
                .addParameter("state", state)
                .addParameter(query.name, query.value)
                .addParameter("client_metadata", clientMetadata.toString())
                .addParameter("transaction_data", transactionData.toString())
                .build()
            val resolution = resolver.resolveRequestUri(authorizationUrl.toString())
            block(resolution)
        }

        @Test
        fun `if transaction_data contains non base64url encoded values, resolution fails`() = runTest {
            val transactionData = JsonArray(listOf(JsonPrimitive("invalid")))
            testAndThen(transactionData) {
                val error = it.validateInvalid<ResolutionError.InvalidTransactionData>()
                val cause = assertIs<IllegalArgumentException>(error.cause)
                assertEquals("The pad bits must be zeros", cause.message)
            }
        }

        @Test
        fun `if transaction_data contains non JsonObject values, resolution fails`() = runTest {
            val transactionData = JsonArray(listOf(JsonPrimitive(base64UrlNoPadding.encode("foo".encodeToByteArray()))))
            testAndThen(transactionData) {
                val error = it.validateInvalid<ResolutionError.InvalidTransactionData>()
                val cause = assertIs<SerializationException>(error.cause)
                assertEquals(
                    "Unexpected JSON token at offset 0: Expected start of the object '{', but had 'f' instead at path: \$\nJSON input: foo",
                    cause.message,
                )
            }
        }

        @Test
        fun `if transaction_data contains no type, resolution fails`() = runTest {
            val transactionData = JsonArray(
                listOf(
                    JsonPrimitive(base64UrlNoPadding.encode(JsonObject(emptyMap()).toString().encodeToByteArray())),
                ),
            )
            testAndThen(transactionData) {
                val error = it.validateInvalid<ResolutionError.InvalidTransactionData>()
                val cause = assertIs<IllegalArgumentException>(error.cause)
                assertEquals(
                    "Missing required property 'type'",
                    cause.message,
                )
            }
        }

        @Test
        fun `if transaction_data contains non-string type, resolution fails`() = runTest {
            val transactionData = JsonArray(
                listOf(
                    buildJsonObject {
                        put("type", 10)
                    }.let {
                        JsonPrimitive(base64UrlNoPadding.encode(it.toString().encodeToByteArray()))
                    },
                ),
            )
            testAndThen(transactionData) {
                val error = it.validateInvalid<ResolutionError.InvalidTransactionData>()
                val cause = assertIs<IllegalArgumentException>(error.cause)
                assertEquals(
                    "Property 'type' is not a string'",
                    cause.message,
                )
            }
        }

        @Test
        fun `if transaction_data contains unsupported type, resolution fails`() = runTest {
            val transactionData = JsonArray(
                listOf(
                    TransactionData(TransactionDataType("unsupported"), listOf(TransactionDataCredentialId("foo"))),
                ).map { JsonPrimitive(it.base64()) },
            )
            testAndThen(transactionData) {
                val error = it.validateInvalid<ResolutionError.InvalidTransactionData>()
                val cause = assertIs<IllegalArgumentException>(error.cause)
                assertEquals(
                    "Unsupported transaction_data 'type': 'unsupported'",
                    cause.message,
                )
            }
        }

        @Test
        fun `if transaction_data contains no credential_ids, resolution fails`() = runTest {
            val transactionData = JsonArray(
                listOf(
                    buildJsonObject {
                        put("type", "basic-transaction-data")
                    }.let {
                        JsonPrimitive(base64UrlNoPadding.encode(it.toString().encodeToByteArray()))
                    },
                ),
            )
            testAndThen(transactionData) {
                val error = it.validateInvalid<ResolutionError.InvalidTransactionData>()
                val cause = assertIs<IllegalArgumentException>(error.cause)
                assertEquals(
                    "Missing required property 'credential_ids'",
                    cause.message,
                )
            }
        }

        @Test
        fun `if transaction_data contains non-string credential_ids, resolution fails`() = runTest {
            val transactionData = JsonArray(
                listOf(
                    buildJsonObject {
                        put("type", "basic-transaction-data")
                        putJsonArray("credential_ids") {
                            add(10)
                        }
                    }.let {
                        JsonPrimitive(base64UrlNoPadding.encode(it.toString().encodeToByteArray()))
                    },
                ),
            )
            testAndThen(transactionData) {
                val error = it.validateInvalid<ResolutionError.InvalidTransactionData>()
                val cause = assertIs<IllegalArgumentException>(error.cause)
                assertEquals(
                    "Property 'credential_ids' is not an array or contains non string values",
                    cause.message,
                )
            }
        }

        @Test
        fun `if transaction_data contains credential_ids that don't match inputdescriptor ids, resolution fails`() =
            runTest {
                val transactionData = JsonArray(
                    listOf(
                        buildJsonObject {
                            put("type", "basic-transaction-data")
                            putJsonArray("credential_ids") {
                                add("invalid-id")
                            }
                        }.let {
                            JsonPrimitive(base64UrlNoPadding.encode(it.toString().encodeToByteArray()))
                        },
                    ),
                )
                testAndThen(transactionData) {
                    val error = it.validateInvalid<ResolutionError.InvalidTransactionData>()
                    val cause = assertIs<IllegalArgumentException>(error.cause)
                    assertEquals(
                        "Invalid 'credential_ids': '[invalid-id]'",
                        cause.message,
                    )
                }
            }

        @Test
        fun `if transaction_data contains credential_ids that don't match query ids, resolution fails`() = runTest {
            val transactionData = JsonArray(
                listOf(
                    buildJsonObject {
                        put("type", "basic-transaction-data")
                        putJsonArray("credential_ids") {
                            add("invalid-id")
                        }
                    }.let {
                        JsonPrimitive(base64UrlNoPadding.encode(it.toString().encodeToByteArray()))
                    },
                ),
            )
            testAndThen(transactionData, dcqlQuery) {
                val error = it.validateInvalid<ResolutionError.InvalidTransactionData>()
                val cause = assertIs<IllegalArgumentException>(error.cause)
                assertEquals(
                    "Invalid 'credential_ids': '[invalid-id]'",
                    cause.message,
                )
            }
        }

        @Test
        fun `if transaction_data contains non-list transaction_data_hashes_alg, resolution fails`() = runTest {
            val transactionData = JsonArray(
                listOf(
                    buildJsonObject {
                        put("type", "basic-transaction-data")
                        putJsonArray("credential_ids") {
                            add("my_credential")
                        }
                        put("transaction_data_hashes_alg", "invalid")
                    }.let {
                        JsonPrimitive(base64UrlNoPadding.encode(it.toString().encodeToByteArray()))
                    },
                ),
            )
            testAndThen(transactionData, dcqlQuery) {
                val error = it.validateInvalid<ResolutionError.InvalidTransactionData>()
                val cause = assertIs<IllegalArgumentException>(error.cause)
                assertEquals(
                    "Property 'transaction_data_hashes_alg' is not an array or contains non string values",
                    cause.message,
                )
            }
        }

        @Test
        fun `if transaction_data contains non-string transaction_data_hashes_alg, resolution fails`() = runTest {
            val transactionData = JsonArray(
                listOf(
                    buildJsonObject {
                        put("type", "basic-transaction-data")
                        putJsonArray("credential_ids") {
                            add("my_credential")
                        }
                        putJsonArray("transaction_data_hashes_alg") {
                            add(15)
                        }
                    }.let {
                        JsonPrimitive(base64UrlNoPadding.encode(it.toString().encodeToByteArray()))
                    },
                ),
            )
            testAndThen(transactionData, dcqlQuery) {
                val error = it.validateInvalid<ResolutionError.InvalidTransactionData>()
                val cause = assertIs<IllegalArgumentException>(error.cause)
                assertEquals(
                    "Property 'transaction_data_hashes_alg' is not an array or contains non string values",
                    cause.message,
                )
            }
        }

        @Test
        fun `if transaction_data contains unsupported transaction_data_hashes_alg, resolution fails`() = runTest {
            val transactionData = JsonArray(
                listOf(
                    TransactionData(
                        TransactionDataType("basic-transaction-data"),
                        listOf(TransactionDataCredentialId("my_credential")),
                        listOf(HashAlgorithm("sha-512")),
                    ),
                ).map { JsonPrimitive(it.base64()) },
            )
            testAndThen(transactionData, dcqlQuery) {
                val error = it.validateInvalid<ResolutionError.InvalidTransactionData>()
                val cause = assertIs<IllegalArgumentException>(error.cause)
                assertEquals(
                    "Unsupported 'transaction_data_hashes_alg': '[sha-512]'",
                    cause.message,
                )
            }
        }

        @Test
        fun `if transaction_data is valid, when using dcql, resolution succeeds`() = runTest {
            val transactionData = JsonArray(
                listOf(
                    buildJsonObject {
                        put("type", "basic-transaction-data")
                        putJsonArray("credential_ids") {
                            add("my_credential")
                        }
                        putJsonArray("transaction_data_hashes_alg") {
                            add("sha-256")
                        }
                    }.let {
                        JsonPrimitive(base64UrlNoPadding.encode(it.toString().encodeToByteArray()))
                    },
                ),
            )
            testAndThen(transactionData, dcqlQuery) {
                val request = it.validateSuccess<ResolvedRequestObject.OpenId4VPAuthorization>()
                val resolvedTransactionData = run {
                    val resolvedTransactionData = assertNotNull(request.transactionData)
                    assertEquals(1, resolvedTransactionData.size)
                    resolvedTransactionData.first()
                }
                assertEquals(TransactionDataType("basic-transaction-data"), resolvedTransactionData.type)
                assertEquals(
                    listOf(TransactionDataCredentialId("my_credential")),
                    resolvedTransactionData.credentialIds,
                )
                assertEquals(listOf(HashAlgorithm.SHA_256), resolvedTransactionData.hashAlgorithms)
            }
        }

        @Test
        fun `if transaction_data is valid, when using presentationexchange, resolution succeeds`() = runTest {
            val transactionData = JsonArray(
                listOf(
                    buildJsonObject {
                        put("type", "basic-transaction-data")
                        putJsonArray("credential_ids") {
                            add("bankaccount_input")
                        }
                        putJsonArray("transaction_data_hashes_alg") {
                            add("sha-256")
                        }
                    }.let {
                        JsonPrimitive(base64UrlNoPadding.encode(it.toString().encodeToByteArray()))
                    },
                ),
            )
            testAndThen(transactionData) {
                val request = it.validateSuccess<ResolvedRequestObject.OpenId4VPAuthorization>()
                val resolvedTransactionData = run {
                    val resolvedTransactionData = assertNotNull(request.transactionData)
                    assertEquals(1, resolvedTransactionData.size)
                    resolvedTransactionData.first()
                }
                assertEquals(TransactionDataType("basic-transaction-data"), resolvedTransactionData.type)
                assertEquals(
                    listOf(TransactionDataCredentialId("bankaccount_input")),
                    resolvedTransactionData.credentialIds,
                )
                assertEquals(listOf(HashAlgorithm.SHA_256), resolvedTransactionData.hashAlgorithms)
            }
        }

        @Test
        fun `if transaction_data is valid, and contains no transaction_data_hashes_alg, resolution succeeds`() =
            runTest {
                val transactionData = JsonArray(
                    listOf(
                        buildJsonObject {
                            put("type", "basic-transaction-data")
                            putJsonArray("credential_ids") {
                                add("bankaccount_input")
                            }
                        }.let {
                            JsonPrimitive(base64UrlNoPadding.encode(it.toString().encodeToByteArray()))
                        },
                    ),
                )
                testAndThen(transactionData) {
                    val request = it.validateSuccess<ResolvedRequestObject.OpenId4VPAuthorization>()
                    val resolvedTransactionData = run {
                        val resolvedTransactionData = assertNotNull(request.transactionData)
                        assertEquals(1, resolvedTransactionData.size)
                        resolvedTransactionData.first()
                    }
                    assertEquals(TransactionDataType("basic-transaction-data"), resolvedTransactionData.type)
                    assertEquals(
                        listOf(TransactionDataCredentialId("bankaccount_input")),
                        resolvedTransactionData.credentialIds,
                    )
                    assertEquals(listOf(HashAlgorithm.SHA_256), resolvedTransactionData.hashAlgorithms)
                }
            }

        @Test
        fun `if transaction_data is valid, and contains transaction_data_hashes_alg without sha-256, resolution succeeds`() =
            runTest {
                val transactionData = JsonArray(
                    listOf(
                        buildJsonObject {
                            put("type", "basic-transaction-data")
                            putJsonArray("credential_ids") {
                                add("bankaccount_input")
                            }
                            putJsonArray("transaction_data_hashes_alg") {
                                add("sha-384")
                            }
                        }.let {
                            JsonPrimitive(base64UrlNoPadding.encode(it.toString().encodeToByteArray()))
                        },
                    ),
                )
                testAndThen(transactionData) {
                    val request = it.validateSuccess<ResolvedRequestObject.OpenId4VPAuthorization>()
                    val resolvedTransactionData = run {
                        val resolvedTransactionData = assertNotNull(request.transactionData)
                        assertEquals(1, resolvedTransactionData.size)
                        resolvedTransactionData.first()
                    }
                    assertEquals(TransactionDataType("basic-transaction-data"), resolvedTransactionData.type)
                    assertEquals(
                        listOf(TransactionDataCredentialId("bankaccount_input")),
                        resolvedTransactionData.credentialIds,
                    )
                    assertEquals(listOf(HashAlgorithm("sha-384")), resolvedTransactionData.hashAlgorithms)
                }
            }
    }
}

object Jackson {
    private val objectMapper: ObjectMapper by lazy { ObjectMapper() }

    fun toJsonObject(pd: PresentationDefinition): Any {
        val jsonStr = with(PresentationExchange.jsonParser) { pd.encode() }
        return objectMapper.readValue<Any>(jsonStr)
    }

    internal fun toJsonObject(metadata: UnvalidatedClientMetaData): Any {
        val jsonStr = Json.encodeToString(metadata)
        return objectMapper.readValue<Any>(jsonStr)
    }
}
