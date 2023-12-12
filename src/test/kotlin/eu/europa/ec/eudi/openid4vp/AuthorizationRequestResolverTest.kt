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
import kotlinx.coroutines.test.runTest
import kotlinx.serialization.ExperimentalSerializationApi
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.decodeFromStream
import kotlinx.serialization.json.jsonObject
import java.io.File
import java.io.InputStream
import java.net.URLEncoder
import java.security.KeyStore
import java.security.cert.X509Certificate
import java.time.Duration
import java.util.*
import kotlin.test.Test
import kotlin.test.assertTrue
import kotlin.test.fail

class AuthorizationRequestResolverTest {

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

    private val jwkSet = Json.parseToJsonElement(
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

    private val walletConfig = WalletOpenId4VPConfig(
        presentationDefinitionUriSupported = true,
        supportedClientIdSchemes = listOf(
            SupportedClientIdScheme.Preregistered(
                mapOf(
                    "Verifier" to
                            PreregisteredClient(
                                clientId = "Verifier",
                                jarSigningAlg = "RS256",
                                jwkSetSource = JwkSetSource.ByValue(jwkSet),
                            ),
                ),
            ),
            SupportedClientIdScheme.X509SanDns(::validateChain),
            SupportedClientIdScheme.X509SanUri(::validateChain),
        ),
        vpFormatsSupported = emptyList(),
        subjectSyntaxTypesSupported = listOf(
            SubjectSyntaxType.JWKThumbprint,
            SubjectSyntaxType.DecentralizedIdentifier.parse("did:example"),
            SubjectSyntaxType.DecentralizedIdentifier.parse("did:key"),
        ),
        signingKey = signingKey,
        signingKeySet = JWKSet(signingKey),
        idTokenTTL = Duration.ofMinutes(10),
        preferredSubjectSyntaxType = SubjectSyntaxType.JWKThumbprint,
        decentralizedIdentifier = "DID:example:12341512#$",
        authorizationSigningAlgValuesSupported = emptyList(),
        authorizationEncryptionAlgValuesSupported = emptyList(),
        authorizationEncryptionEncValuesSupported = emptyList(),
    )

    private val resolver = SiopOpenId4Vp(walletConfig)

    private val clientMetadataJwksInline =
        """ {
             "jwks": $jwkSet,
             "id_token_encrypted_response_alg": "RS256", 
             "id_token_encrypted_response_enc": "A128CBC-HS256", 
             "subject_syntax_types_supported": [ "urn:ietf:params:oauth:jwk-thumbprint", "did:example", "did:key" ], 
             "id_token_signed_response_alg": "RS256" 
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
                    "&client_metadata=$clientMetadataJwksInline"

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
        val authRequest =
            """
             http://localhost:8080/public_url?client_id=Verifier&request=eyJraWQiOiJhMDc3OWNkZS0wNjE1LTQxYjMtODliNy1hZWM3NWZhYTE1OWQiLCJ0eXAiOiJvYXV0aC1hdXRoei1yZXErand0IiwiYWxnIjoiUlMyNTYifQ.eyJyZXNwb25zZV91cmkiOiJodHRwczovL2V1ZGkubmV0Y29tcGFueS1pbnRyYXNvZnQuY29tL3dhbGxldC9kaXJlY3RfcG9zdCIsImNsaWVudF9pZF9zY2hlbWUiOiJwcmUtcmVnaXN0ZXJlZCIsInJlc3BvbnNlX3R5cGUiOiJ2cF90b2tlbiIsIm5vbmNlIjoibm9uY2UiLCJjbGllbnRfaWQiOiJWZXJpZmllciIsInJlc3BvbnNlX21vZGUiOiJkaXJlY3RfcG9zdCIsImF1ZCI6Imh0dHBzOi8vc2VsZi1pc3N1ZWQubWUvdjIiLCJzY29wZSI6IiIsInByZXNlbnRhdGlvbl9kZWZpbml0aW9uIjp7ImlkIjoiMzJmNTQxNjMtNzE2Ni00OGYxLTkzZDgtZmYyMTdiZGIwNjUzIiwiaW5wdXRfZGVzY3JpcHRvcnMiOlt7ImlkIjoiZXVkaV9waWQiLCJuYW1lIjoiRVVESSBQSUQiLCJwdXJwb3NlIjoiV2UgbmVlZCB0byB2ZXJpZnkgeW91ciBpZGVudGl0eSIsImNvbnN0cmFpbnRzIjp7ImZpZWxkcyI6W3sicGF0aCI6WyIkLm1kb2MuZG9jdHlwZSJdLCJmaWx0ZXIiOnsidHlwZSI6InN0cmluZyIsImNvbnN0IjoiZXUuZXVyb3BhLmVjLmV1ZGl3LnBpZC4xIn19LHsicGF0aCI6WyIkLm1kb2MubmFtZXNwYWNlIl0sImZpbHRlciI6eyJ0eXBlIjoic3RyaW5nIiwiY29uc3QiOiJldS5ldXJvcGEuZWMuZXVkaXcucGlkLjEifX0seyJwYXRoIjpbIiQubWRvYy5mYW1pbHlfbmFtZSJdLCJpbnRlbnRfdG9fcmV0YWluIjpmYWxzZX0seyJwYXRoIjpbIiQubWRvYy5naXZlbl9uYW1lIl0sImludGVudF90b19yZXRhaW4iOmZhbHNlfSx7InBhdGgiOlsiJC5tZG9jLmJpcnRoX2RhdGUiXSwiaW50ZW50X3RvX3JldGFpbiI6ZmFsc2V9LHsicGF0aCI6WyIkLm1kb2MuYWdlX292ZXJfMTgiXSwiaW50ZW50X3RvX3JldGFpbiI6ZmFsc2V9LHsicGF0aCI6WyIkLm1kb2MuYWdlX2luX3llYXJzIl0sImludGVudF90b19yZXRhaW4iOmZhbHNlfSx7InBhdGgiOlsiJC5tZG9jLmFnZV9iaXJ0aF95ZWFyIl0sImludGVudF90b19yZXRhaW4iOmZhbHNlfSx7InBhdGgiOlsiJC5tZG9jLmZhbWlseV9uYW1lX2JpcnRoIl0sImludGVudF90b19yZXRhaW4iOmZhbHNlfSx7InBhdGgiOlsiJC5tZG9jLmdpdmVuX25hbWVfYmlydGgiXSwiaW50ZW50X3RvX3JldGFpbiI6ZmFsc2V9LHsicGF0aCI6WyIkLm1kb2MuYmlydGhfcGxhY2UiXSwiaW50ZW50X3RvX3JldGFpbiI6ZmFsc2V9LHsicGF0aCI6WyIkLm1kb2MuYmlydGhfY291bnRyeSJdLCJpbnRlbnRfdG9fcmV0YWluIjpmYWxzZX0seyJwYXRoIjpbIiQubWRvYy5iaXJ0aF9zdGF0ZSJdLCJpbnRlbnRfdG9fcmV0YWluIjpmYWxzZX0seyJwYXRoIjpbIiQubWRvYy5iaXJ0aF9jaXR5Il0sImludGVudF90b19yZXRhaW4iOmZhbHNlfSx7InBhdGgiOlsiJC5tZG9jLnJlc2lkZW50X2FkZHJlc3MiXSwiaW50ZW50X3RvX3JldGFpbiI6ZmFsc2V9LHsicGF0aCI6WyIkLm1kb2MucmVzaWRlbnRfY291bnRyeSJdLCJpbnRlbnRfdG9fcmV0YWluIjpmYWxzZX0seyJwYXRoIjpbIiQubWRvYy5yZXNpZGVudF9zdGF0ZSJdLCJpbnRlbnRfdG9fcmV0YWluIjpmYWxzZX0seyJwYXRoIjpbIiQubWRvYy5yZXNpZGVudF9jaXR5Il0sImludGVudF90b19yZXRhaW4iOmZhbHNlfSx7InBhdGgiOlsiJC5tZG9jLnJlc2lkZW50X3Bvc3RhbF9jb2RlIl0sImludGVudF90b19yZXRhaW4iOmZhbHNlfSx7InBhdGgiOlsiJC5tZG9jLnJlc2lkZW50X3N0cmVldCJdLCJpbnRlbnRfdG9fcmV0YWluIjpmYWxzZX0seyJwYXRoIjpbIiQubWRvYy5yZXNpZGVudF9ob3VzZV9udW1iZXIiXSwiaW50ZW50X3RvX3JldGFpbiI6ZmFsc2V9LHsicGF0aCI6WyIkLm1kb2MuZ2VuZGVyIl0sImludGVudF90b19yZXRhaW4iOmZhbHNlfSx7InBhdGgiOlsiJC5tZG9jLm5hdGlvbmFsaXR5Il0sImludGVudF90b19yZXRhaW4iOmZhbHNlfSx7InBhdGgiOlsiJC5tZG9jLmlzc3VhbmNlX2RhdGUiXSwiaW50ZW50X3RvX3JldGFpbiI6ZmFsc2V9LHsicGF0aCI6WyIkLm1kb2MuZXhwaXJ5X2RhdGUiXSwiaW50ZW50X3RvX3JldGFpbiI6ZmFsc2V9LHsicGF0aCI6WyIkLm1kb2MuaXNzdWluZ19hdXRob3JpdHkiXSwiaW50ZW50X3RvX3JldGFpbiI6ZmFsc2V9LHsicGF0aCI6WyIkLm1kb2MuZG9jdW1lbnRfbnVtYmVyIl0sImludGVudF90b19yZXRhaW4iOmZhbHNlfSx7InBhdGgiOlsiJC5tZG9jLmFkbWluaXN0cmF0aXZlX251bWJlciJdLCJpbnRlbnRfdG9fcmV0YWluIjpmYWxzZX0seyJwYXRoIjpbIiQubWRvYy5pc3N1aW5nX2NvdW50cnkiXSwiaW50ZW50X3RvX3JldGFpbiI6ZmFsc2V9LHsicGF0aCI6WyIkLm1kb2MuaXNzdWluZ19qdXJpc2RpY3Rpb24iXSwiaW50ZW50X3RvX3JldGFpbiI6ZmFsc2V9XX19XX0sInN0YXRlIjoiNjM4SndIMGIyanJoR2xBWlFWYTUwS3lzVmF6a0ktWXBpRmNMajJETE1hbEpwWks2WEMyMnZBc1BxWGtwd0F3WHpmWXBLLVdMYzNHaEhZSzhsYlQ2cnciLCJpYXQiOjE3MDE5NzAzOTQsImNsaWVudF9tZXRhZGF0YSI6eyJqd2tzIjp7ImtleXMiOlt7Imt0eSI6IlJTQSIsImUiOiJBUUFCIiwidXNlIjoic2lnIiwia2lkIjoiYTA3NzljZGUtMDYxNS00MWIzLTg5YjctYWVjNzVmYWExNTlkIiwiaWF0IjoxNzAxNDM2MDAxLCJuIjoiazRnejhINFJ2dWg3U2hQSHBPd1NQTjlTV1dCVXhBcGdPdUJZekRRT2E0clhNbVVzMjBlZ1JPdnREUVlmMkMwby1tWkVQVVhOcTgtSTc5djlqX1VhY3VtMkNRV3BPUGQ3Wi1rWEdac0U3WjlIQXFWUHFRbk1OVVUyYVFQYzhXWWJrclhPckZqRklvMEdRdVZPYlZNTl8xd2gyazk0SkxGb3FSQXgyVExNclJ1LXBRVVFmTjFpVEwtMnlMM0NuLVJpM1dfc3hoZExWMHVLZHZpS2NVNDM3TGR2cnBFM2VvWGVQeG9mbUR4RzJ1ZFg2VFNxTnZ6UlpwS1I5VnF5OWhLYVRwcEFIcF8wRzFmUTRkU0NMcFNZOWh4R0V1VEZnRkF5dnRaWmhackwyT0ZhNlhIUEM2MHVYNS1JaXIySzBJeW1TUHJWcGZ0eE5VQUNLZWJraDVGVEd3In1dfSwiaWRfdG9rZW5fZW5jcnlwdGVkX3Jlc3BvbnNlX2FsZyI6IlJTMjU2IiwiaWRfdG9rZW5fZW5jcnlwdGVkX3Jlc3BvbnNlX2VuYyI6IkExMjhDQkMtSFMyNTYiLCJzdWJqZWN0X3N5bnRheF90eXBlc19zdXBwb3J0ZWQiOlsidXJuOmlldGY6cGFyYW1zOm9hdXRoOmp3ay10aHVtYnByaW50IiwiZGlkOmV4YW1wbGUiLCJkaWQ6a2V5Il0sImlkX3Rva2VuX3NpZ25lZF9yZXNwb25zZV9hbGciOiJSUzI1NiJ9fQ.BNfrJYKjKOUSmw1EMMhwebbMcjNs3UZ3AWRup9EkUMijcCeHIHEoSMvL8dnaV1Mg8D6zRrBE9S0qqCotaUHv4SCBO0BG76Iw67TTv7Pdm-3cg_nCmTqOglam8ZqypRHaTljRzJMC-kMn40tOi4pDzbDU4RQzWK3Xq-CvRE-t48zj5Dr01648MRjW78kFib3-dkYg_GuzR6qeqeTcToMqglay6fKn6nup2Xdz5RvwuBday6vG0eTZB2q9dl_ouyjShNGryIUiN6OP-y9Pbi2NeLlKAMmn8drkhXvoNvkvXTG3pOKuWzLgcl0p7AZuBRdW_Nd3OjTttTeJVmu82MZvUQ
            """.trimIndent()

        val resolution = resolver.resolveRequestUri(authRequest)

        resolution.validateSuccess<ResolvedRequestObject.OpenId4VPAuthorization>()
    }

    @Test
    fun `JAR auth request, request passed as JWT, verified with x509_san_dns scheme`() = runTest {
        val keyStore = KeyStore.getInstance("JKS")
        keyStore.load(
            load("certificates/certificates.jks"),
            "12345".toCharArray(),
        )
        val signedJwt = createSignedRequestJwt(keyStore, "request-object/request_object_claimset-san_dns.json")
        val authRequest = "http://localhost:8080/public_url?client_id=verifier.example.gr&request=$signedJwt"

        val resolution = resolver.resolveRequestUri(authRequest)
        resolution.validateSuccess<ResolvedRequestObject.OpenId4VPAuthorization>()
    }

    @Test
    fun `JAR auth request, request passed as JWT, verified with x509_san_uri scheme`() = runTest {
        val keyStore = KeyStore.getInstance("JKS")
        keyStore.load(
            load("certificates/certificates.jks"),
            "12345".toCharArray(),
        )
        val signedJwt = createSignedRequestJwt(keyStore, "request-object/request_object_claimset-san_uri.json")
        val authRequest = "http://localhost:8080/public_url?client_id=https%3A%2F%2Fverifier.example.gr&request=$signedJwt"

        val resolution = resolver.resolveRequestUri(authRequest)
        resolution.validateSuccess<ResolvedRequestObject.OpenId4VPAuthorization>()
    }

    private fun createSignedRequestJwt(keyStore: KeyStore, resourcePath: String): String {
        val chain = keyStore.getCertificateChain("verifierexample")
        val base64EncodedChain = chain.map {
            com.nimbusds.jose.util.Base64.encode(it.encoded)
        }

        val resource =
            AuthorizationRequestResolverTest::class.java.classLoader.getResource(resourcePath)
                ?: error("Source file not found.")
        val text = File(resource.toURI()).readText(Charsets.UTF_8)
        val claimSet = JWTClaimsSet.parse(text)

        val headerBuilder = JWSHeader.Builder(JWSAlgorithm.RS256)
        headerBuilder.x509CertChain(base64EncodedChain.toMutableList())
        headerBuilder.type(JOSEObjectType("oauth-authz-req+jwt"))

        val signedJWT = SignedJWT(headerBuilder.build(), claimSet)

        val jwkSet = JWKSet.load(keyStore, { keyName -> "12345".toCharArray() })
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
        AuthorizationRequestResolverTest::class.java.classLoader.getResourceAsStream(f) ?: error("File $f not found")

    private inline fun <reified T : ResolvedRequestObject> Resolution.validateSuccess() {
        when (this) {
            is Resolution.Success -> assertTrue("${T::class} data expected") {
                this.requestObject is T
            }

            else -> fail("Invalid resolution found while expected success")
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
