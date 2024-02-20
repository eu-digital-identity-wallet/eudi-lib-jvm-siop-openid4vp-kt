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
import eu.europa.ec.eudi.openid4vp.internal.request.DefaultAuthorizationRequestResolver
import eu.europa.ec.eudi.openid4vp.internal.request.UnvalidatedClientMetaData
import eu.europa.ec.eudi.prex.PresentationDefinition
import eu.europa.ec.eudi.prex.PresentationExchange
import kotlinx.coroutines.test.runTest
import kotlinx.serialization.ExperimentalSerializationApi
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.decodeFromStream
import kotlinx.serialization.json.jsonObject
import java.io.InputStream
import java.net.URI
import java.net.URLEncoder
import java.security.KeyStore
import java.security.cert.X509Certificate
import java.util.*
import kotlin.test.Test
import kotlin.test.assertTrue
import kotlin.test.fail

class UnvalidatedRequestResolverTest {

    private val json: Json by lazy { Json { ignoreUnknownKeys = true } }

    private val pd = readFileAsText("presentation-definition/basic_example.json")
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
        val authRequest =
            "https://client.example.org/universal-link?" +
                "response_type=vp_token" +
                "&client_id=https%3A%2F%2Fclient.example.org%2Fcb" +
                "&client_id_scheme=redirect_uri" +
                "&redirect_uri=https%3A%2F%2Fclient.example.org%2Fcb" +
                "&nonce=n-0S6_WzA2Mj" +
                "&state=${genState()}" +
                "&presentation_definition=$pd" +
                "&client_metadata=$clientMetadataJwksInlineNoSubjectSyntaxTypes"

        val resolution = resolver.resolveRequestUri(authRequest)

        resolution.validateSuccess<ResolvedRequestObject.OpenId4VPAuthorization>()
    }

    @Test
    fun `id token auth request`() = runTest {
        val authRequest =
            "https://client.example.org/universal-link?" +
                "response_type=id_token" +
                "&client_id=https%3A%2F%2Fclient.example.org%2Fcb" +
                "&client_id_scheme=redirect_uri" +
                "&redirect_uri=https%3A%2F%2Fclient.example.org%2Fcb" +
                "&nonce=n-0S6_WzA2Mj" +
                "&state=${genState()}" +
                "&scope=openid" +
                "&client_metadata=$clientMetadataJwksInline"

        val resolution = resolver.resolveRequestUri(authRequest)

        resolution.validateSuccess<ResolvedRequestObject.SiopAuthentication>()
    }

    @Test
    fun `id and vp token auth request`() = runTest {
        val authRequest =
            "https://client.example.org/universal-link?" +
                "response_type=id_token vp_token" +
                "&client_id=https%3A%2F%2Fclient.example.org%2Fcb" +
                "&client_id_scheme=redirect_uri" +
                "&redirect_uri=https%3A%2F%2Fclient.example.org%2Fcb" +
                "&nonce=n-0S6_WzA2Mj" +
                "&scope=openid" +
                "&state=${genState()}" +
                "&presentation_definition=$pd" +
                "&client_metadata=$clientMetadataJwksInline"

        val resolution = resolver.resolveRequestUri(authRequest)

        resolution.validateSuccess<ResolvedRequestObject.SiopOpenId4VPAuthentication>()
    }

    @Test
    fun `JAR auth request, request passed as JWT, verified with pre-registered client scheme`() = runTest {
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
                "pre-registered",
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
            val clientId = "verifier.example.gr"
            val jwtClaimsSet = jwtClaimsSet(
                clientId,
                "x509_san_dns",
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
            val clientId: URI = URI.create("https://verifier.example.gr")
            val clientIdEncoded = URLEncoder.encode(clientId.toString(), "UTF-8")
            val jwtClaimsSet = jwtClaimsSet(
                clientId.toString(),
                "x509_san_uri",
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
        clientIdScheme: String,
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
            claim("client_id_scheme", clientIdScheme)
            claim("response_uri", responseUri)
            claim("response_type", "vp_token")
            claim("nonce", "nonce")
            claim("response_mode", "direct_post")
            claim("scope", "")
            claim("presentation_definition", Jackson.toJsonObject(presentationDefinition))
            claim("state", "638JwH0b2jrhGlAZQVa50KysVazkI-YpiFcLj2DLMalJpZK6XC22vAsPqXkpwAwXzfYpK-WLc3GhHYK8lbT6rw")
            claim("client_metadata", Jackson.toJsonObject(clientMetadata))
            build()
        }
    }

    @Test
    fun `response type provided comma separated`() = runTest {
        val authRequest =
            "https://client.example.org/universal-link?" +
                "response_type=id_token,vp_token" +
                "&client_id=https%3A%2F%2Fclient.example.org%2Fcb" +
                "&client_id_scheme=redirect_uri" +
                "&redirect_uri=https%3A%2F%2Fclient.example.org%2Fcb" +
                "&nonce=n-0S6_WzA2Mj" +
                "&state=${genState()}" +
                "&client_metadata=$clientMetadataJwksInline"

        val resolution = resolver.resolveRequestUri(authRequest)

        resolution.validateInvalid<RequestValidationError.UnsupportedResponseType>()
    }

    @Test
    fun `response type provided is miss-spelled`() = runTest {
        val authRequest =
            "https://client.example.org/universal-link?" +
                "response_type=id_tokens" +
                "&client_id=https%3A%2F%2Fclient.example.org%2Fcb" +
                "&client_id_scheme=redirect_uri" +
                "&redirect_uri=https%3A%2F%2Fclient.example.org%2Fcb" +
                "&nonce=n-0S6_WzA2Mj" +
                "&state=${genState()}" +
                "&client_metadata=$clientMetadataJwksInline"

        val resolution = resolver.resolveRequestUri(authRequest)

        resolution.validateInvalid<RequestValidationError.UnsupportedResponseType>()
    }

    @Test
    fun `nonce validation`() = runTest {
        val authRequest =
            "https://client.example.org/universal-link?" +
                "response_type=id_token" +
                "&client_id=https%3A%2F%2Fclient.example.org%2Fcb" +
                "&client_id_scheme=redirect_uri" +
                "&state=${genState()}" +
                "&redirect_uri=https%3A%2F%2Fclient.example.org%2Fcb" +
                "&client_metadata=$clientMetadataJwksInline"

        val resolution = resolver.resolveRequestUri(authRequest)

        resolution.validateInvalid<RequestValidationError.MissingNonce>()
    }

    @Test
    fun `if client_id is missing reject the request`() = runTest {
        val authRequest =
            "https://client.example.org/universal-link?" +
                "response_type=id_token" +
                "&client_id_scheme=redirect_uri" +
                "&redirect_uri=https%3A%2F%2Fclient.example.org%2Fcb" +
                "&nonce=n-0S6_WzA2Mj" +
                "&state=${genState()}" +
                "&client_metadata=$clientMetadataJwksInline"

        val resolution = resolver.resolveRequestUri(authRequest)

        resolution.validateInvalid<RequestValidationError.MissingClientId>()
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

    private inline fun <reified T : ResolvedRequestObject> Resolution.validateSuccess() {
        when (this) {
            is Resolution.Success -> assertTrue("${T::class} data expected") {
                this.requestObject is T
            }

            is Resolution.Invalid -> fail("Invalid resolution found while expected success\n$error")
        }
    }

    private inline fun <reified T : RequestValidationError> Resolution.validateInvalid() {
        when (this) {
            is Resolution.Invalid -> assertTrue("${T::class} error expected") {
                this.error is T
            }

            else -> fail("Success resolution found while expected Invalid")
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
