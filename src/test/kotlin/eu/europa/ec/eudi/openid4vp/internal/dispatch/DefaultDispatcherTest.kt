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
package eu.europa.ec.eudi.openid4vp.internal.dispatch

import com.eygraber.uri.Uri
import com.eygraber.uri.toUri
import com.nimbusds.jose.*
import com.nimbusds.jose.crypto.ECDHDecrypter
import com.nimbusds.jose.crypto.RSASSAVerifier
import com.nimbusds.jose.jwk.Curve
import com.nimbusds.jose.jwk.KeyUse
import com.nimbusds.jose.jwk.RSAKey
import com.nimbusds.jose.jwk.gen.ECKeyGenerator
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator
import com.nimbusds.jwt.EncryptedJWT
import com.nimbusds.jwt.JWTClaimsSet
import com.nimbusds.jwt.SignedJWT
import com.nimbusds.oauth2.sdk.id.State
import eu.europa.ec.eudi.openid4vp.*
import eu.europa.ec.eudi.openid4vp.internal.request.ClientMetadataValidator
import eu.europa.ec.eudi.openid4vp.internal.request.UnvalidatedClientMetaData
import eu.europa.ec.eudi.prex.Id
import eu.europa.ec.eudi.prex.PresentationDefinition
import eu.europa.ec.eudi.prex.PresentationSubmission
import io.ktor.client.*
import io.ktor.client.engine.mock.*
import io.ktor.client.request.forms.*
import io.ktor.http.*
import io.ktor.util.*
import kotlinx.coroutines.test.runTest
import kotlinx.serialization.json.Json
import org.junit.jupiter.api.DisplayName
import org.junit.jupiter.api.Nested
import org.junit.jupiter.api.assertThrows
import java.net.URI
import java.security.interfaces.ECPrivateKey
import java.util.*
import kotlin.test.*

class DefaultDispatcherTest {

    private val rsaSigningKey = RSAKeyGenerator(2048)
        .keyUse(KeyUse.SIGNATURE)
        .keyID(UUID.randomUUID().toString())
        .issueTime(Date(System.currentTimeMillis()))
        .generate()

    @Nested
    @DisplayName("Encrypted/Signed response")
    inner class DirectPostJwtResponse {

        private val json: Json by lazy { Json { ignoreUnknownKeys = true } }

        private val ecKey = ECKeyGenerator(Curve.P_256)
            .keyUse(KeyUse.ENCRYPTION)
            .algorithm(JWEAlgorithm.ECDH_ES)
            .keyID("123")
            .generate()

        private val rsaKey = (
            "{\"kty\": \"RSA\", \"e\": \"AQAB\", \"use\": \"sig\", \"kid\": \"a4e1bbe6-26e8-480b-a364-f43497894453\"," +
                " \"iat\": 1683559586, \"n\": \"xHI9zoXS-fOAFXDhDmPMmT_UrU1MPimy0xfP-sL0Iu4CQJmGkALiCNzJh9v343fqFT2hfrbigMnafB2wtcXZeE" +
                "Dy6Mwu9QcJh1qLnklW5OOdYsLJLTyiNwMbLQXdVxXiGby66wbzpUymrQmT1v80ywuYd8Y0IQVyteR2jvRDNxy88bd2eosfkUdQhNKUsUmpODSxrEU2SJCC" +
                "lO4467fVdPng7lyzF2duStFeA2vUkZubor3EcrJ72JbZVI51YDAqHQyqKZIDGddOOvyGUTyHz9749bsoesqXHOugVXhc2elKvegwBik3eOLgfYKJwisFcr" +
                "Bl62k90RaMZpXCxNO4Ew\"}"
            ).trimIndent()

        private val walletConfig = WalletOpenId4VPConfig(
            presentationDefinitionUriSupported = true,
            supportedClientIdSchemes = listOf(SupportedClientIdScheme.X509SanDns { _ -> true }),
            vpFormatsSupported = emptyList(),
            holderId = "DID:example:12341512#$",
            authorizationResponseSigners = listOf(DelegatingResponseSigner(rsaSigningKey, JWSAlgorithm.parse("RS256"))),
            authorizationEncryptionAlgValuesSupported = emptyList(),
            authorizationEncryptionEncValuesSupported = emptyList(),
        )

        private val walletConfigWithSignAndEncryptionAlgorithms = WalletOpenId4VPConfig(
            presentationDefinitionUriSupported = true,
            supportedClientIdSchemes = listOf(SupportedClientIdScheme.X509SanDns { _ -> true }),
            vpFormatsSupported = emptyList(),
            holderId = "DID:example:12341512#$",
            authorizationResponseSigners = listOf(DelegatingResponseSigner(rsaSigningKey, JWSAlgorithm.parse("RS256"))),
            authorizationEncryptionAlgValuesSupported = listOf(JWEAlgorithm.parse("ECDH-ES")),
            authorizationEncryptionEncValuesSupported = listOf(EncryptionMethod.parse("A256GCM")),
        )

        @Test
        fun `client metadata does not match with wallet's supported algorithms`(): Unit = runTest {
            val clientMetadataStr = """
                { 
                    "jwks": { "keys": [${ecKey.toPublicJWK().toJSONString()}, $rsaKey ]},
                    "subject_syntax_types_supported": [ "urn:ietf:params:oauth:jwk-thumbprint", "did:example", "did:key" ],
                    "authorization_signed_response_alg":"RS256",
                    "authorization_encrypted_response_alg":"ECDH-ES", 
                    "authorization_encrypted_response_enc":"A256GCM"
                }
            """.trimIndent().trimMargin()
            val clientMetaDataDecoded = json.decodeFromString<UnvalidatedClientMetaData>(clientMetadataStr)
            val responseMode = ResponseMode.QueryJwt(URI.create("foo://bar"))
            assertThrows<Throwable> {
                ClientMetadataValidator(walletConfig, DefaultHttpClientFactory)
                    .validate(clientMetaDataDecoded, responseMode)
            }
        }

        @Test
        fun `if response type direct_post jwt, JWE should be returned if encryption alg specified`() = runTest {
            val responseMode = ResponseMode.DirectPostJwt("https://respond.here".asURL().getOrThrow())
            val clientMetadataStr = """
               { 
                  "jwks": { "keys": [${ecKey.toPublicJWK().toJSONString()}, $rsaKey ]},
                  "subject_syntax_types_supported": [ "urn:ietf:params:oauth:jwk-thumbprint", "did:example", "did:key" ],
                  "authorization_encrypted_response_alg":"ECDH-ES", 
                  "authorization_encrypted_response_enc":"A256GCM"
              }
            """.trimIndent()
            val clientMetaDataDecoded = json.decodeFromString<UnvalidatedClientMetaData>(clientMetadataStr)
            val clientMetadataValidated = ClientMetadataValidator(
                walletConfigWithSignAndEncryptionAlgorithms,
                DefaultHttpClientFactory,
            ).validate(clientMetaDataDecoded, responseMode)

            val resolvedRequest =
                ResolvedRequestObject.OpenId4VPAuthorization(
                    presentationDefinition = PresentationDefinition(
                        id = Id("pdId"),
                        inputDescriptors = emptyList(),
                    ),
                    clientMetaData = clientMetadataValidated,
                    clientId = "https%3A%2F%2Fclient.example.org%2Fcb",
                    nonce = "0S6_WzA2Mj",
                    responseMode = responseMode,
                    state = State().value,
                )

            val vpTokenConsensus = Consensus.PositiveConsensus.VPTokenConsensus(
                "dummy_vp_token",
                PresentationSubmission(Id("psId"), Id("pdId"), emptyList()),
            )
            val response = AuthorizationResponseBuilder(walletConfig).build(resolvedRequest, vpTokenConsensus)
            val mockEngine = MockEngine { request ->
                assertEquals(HttpMethod.Post, request.method)

                val body = assertIs<FormDataContent>(request.body)
                val joseResponse = body.formData["response"] as String
                val decryptedJWT = ecdhDecrypt(ecKey.toECPrivateKey(), joseResponse)

                assertNotNull(decryptedJWT)
                assertNotNull(decryptedJWT.issuer)
                assertNotNull(decryptedJWT.audience)
                assertEquals(decryptedJWT.getClaim("vp_token"), "dummy_vp_token")

                respondOk()
            }

            val outcome = DefaultDispatcher(httpClientFactory = { HttpClient(mockEngine) }).dispatch(response)
            assertEquals(
                DispatchOutcome.VerifierResponse.Accepted(null),
                outcome,
            )
        }

        @Test
        fun `if response type direct_post jwt, JWT should be returned if only signing alg specified`(): Unit = runTest {
            val responseMode = ResponseMode.DirectPostJwt("https://respond.here".asURL().getOrThrow())
            val clientMetadataStr = """
            { 
                "jwks": { "keys": [${ecKey.toPublicJWK().toJSONString()}, $rsaKey ]},                 
                "subject_syntax_types_supported": [ "urn:ietf:params:oauth:jwk-thumbprint", "did:example", "did:key" ],                
                "authorization_signed_response_alg":"RS256",
                "authorization_encrypted_response_alg":"ECDH-ES", 
                "authorization_encrypted_response_enc":"A256GCM"
            }
            """.trimIndent().trimMargin()
            val clientMetaDataDecoded = json.decodeFromString<UnvalidatedClientMetaData>(clientMetadataStr)
            val clientMetadataValidated = ClientMetadataValidator(
                walletConfigWithSignAndEncryptionAlgorithms,
                DefaultHttpClientFactory,
            ).validate(clientMetaDataDecoded, responseMode)

            val resolvedRequest =
                ResolvedRequestObject.OpenId4VPAuthorization(
                    presentationDefinition = PresentationDefinition(
                        id = Id("pdId"),
                        inputDescriptors = emptyList(),
                    ),
                    clientMetaData = clientMetadataValidated,
                    clientId = "https%3A%2F%2Fclient.example.org%2Fcb",
                    nonce = "0S6_WzA2Mj",
                    responseMode = responseMode,
                    state = State().value,
                )

            val vpTokenConsensus = Consensus.PositiveConsensus.VPTokenConsensus(
                "dummy_vp_token",
                PresentationSubmission(Id("psId"), Id("pdId"), emptyList()),
            )
            val response = AuthorizationResponseBuilder(walletConfig).build(resolvedRequest, vpTokenConsensus)

            val mockEngine = MockEngine { request ->
                assertEquals(HttpMethod.Post, request.method)

                val body = assertIs<FormDataContent>(request.body)
                val joseResponse = body.formData["response"] as String
                val encrypted = EncryptedJWT.parse(joseResponse)
                val rsaDecrypter = ECDHDecrypter(ecKey.toECPrivateKey())

                encrypted.decrypt(rsaDecrypter)
                assertEquals(encrypted.state, JWEObject.State.DECRYPTED)

                val signedJWT = encrypted.payload.toSignedJWT()
                signedJWT.verify(RSASSAVerifier(RSAKey.parse(rsaSigningKey.toJSONObject())))
                assertEquals(signedJWT.state, JWSObject.State.VERIFIED)

                assertNotNull(signedJWT.jwtClaimsSet.issuer)
                assertNotNull(signedJWT.jwtClaimsSet.audience)
                assertEquals(signedJWT.jwtClaimsSet.getClaim("vp_token"), "dummy_vp_token")

                respondOk()
            }

            val outcome = DefaultDispatcher(httpClientFactory = { HttpClient(mockEngine) }).dispatch(response)
            assertEquals(
                DispatchOutcome.VerifierResponse.Accepted(null),
                outcome,
            )
        }

        @Test
        @Suppress("ktlint")
        fun `if response type direct_post jwt, JWT should be returned if only signing alg, encryption alg and encryption method are specified and supported by wallet`(): Unit =
            runTest {
                val responseMode = ResponseMode.DirectPostJwt("https://respond.here".asURL().getOrThrow())
                val clientMetadataStr = """
                {
                    "jwks": { "keys": [${ecKey.toPublicJWK().toJSONString()}, $rsaKey ]}, 
                    "id_token_encrypted_response_alg": "RS256", 
                    "id_token_encrypted_response_enc": "A128CBC-HS256", 
                    "subject_syntax_types_supported": [ "urn:ietf:params:oauth:jwk-thumbprint", "did:example", "did:key" ], 
                    "id_token_signed_response_alg": "RS256",
                    "authorization_signed_response_alg":"RS256",
                    "authorization_encrypted_response_alg":"ECDH-ES", 
                    "authorization_encrypted_response_enc":"A256GCM"
                }
                """.trimIndent().trimMargin()
                val clientMetaDataDecoded = json.decodeFromString<UnvalidatedClientMetaData>(clientMetadataStr)
                val clientMetadataValidated =
                    ClientMetadataValidator(walletConfigWithSignAndEncryptionAlgorithms, DefaultHttpClientFactory)
                        .validate(clientMetaDataDecoded, responseMode)

                val resolvedRequest =
                    ResolvedRequestObject.OpenId4VPAuthorization(
                        presentationDefinition = PresentationDefinition(
                            id = Id("pdId"),
                            inputDescriptors = emptyList(),
                        ),
                        clientMetaData = clientMetadataValidated,
                        clientId = "https%3A%2F%2Fclient.example.org%2Fcb",
                        nonce = "0S6_WzA2Mj",
                        responseMode = responseMode,
                        state = State().value,
                    )

                val vpTokenConsensus = Consensus.PositiveConsensus.VPTokenConsensus(
                    "dummy_vp_token",
                    PresentationSubmission(Id("psId"), Id("pdId"), emptyList()),
                )
                val response = AuthorizationResponseBuilder(walletConfigWithSignAndEncryptionAlgorithms)
                    .build(resolvedRequest, vpTokenConsensus)

                val mockEngine = MockEngine { request ->
                    assertEquals(HttpMethod.Post, request.method)

                    val body = assertIs<FormDataContent>(request.body)
                    val joseResponse = body.formData["response"] as String
                    val encrypted = EncryptedJWT.parse(joseResponse)
                    val rsaDecrypter = ECDHDecrypter(ecKey.toECPrivateKey())

                    encrypted.decrypt(rsaDecrypter)
                    assertEquals(encrypted.state, JWEObject.State.DECRYPTED)

                    val signedJWT = encrypted.payload.toSignedJWT()
                    signedJWT.verify(RSASSAVerifier(RSAKey.parse(rsaSigningKey.toJSONObject())))
                    assertEquals(signedJWT.state, JWSObject.State.VERIFIED)

                    assertNotNull(signedJWT.jwtClaimsSet.issuer)
                    assertNotNull(signedJWT.jwtClaimsSet.audience)
                    assertEquals(signedJWT.jwtClaimsSet.getClaim("vp_token"), "dummy_vp_token")

                    respondOk()
                }

                val outcome = DefaultDispatcher(httpClientFactory = { HttpClient(mockEngine) }).dispatch(response)
                assertEquals(
                    DispatchOutcome.VerifierResponse.Accepted(null),
                    outcome
                )
            }

        @Test
        fun `if enc and sign algs specified, JWE should be returned with signed JWT as encrypted payload`() = runTest {
            val responseMode = ResponseMode.DirectPostJwt("https://respond.here".asURL().getOrThrow())
            val clientMetadataStr = """
                { 
                    "jwks": { "keys": [${ecKey.toPublicJWK().toJSONString()}, $rsaKey ]}, 
                    "id_token_encrypted_response_alg": "RS256", 
                    "id_token_encrypted_response_enc": "A128CBC-HS256", 
                    "subject_syntax_types_supported": [ "urn:ietf:params:oauth:jwk-thumbprint", "did:example", "did:key" ], 
                    "id_token_signed_response_alg": "RS256",
                    "authorization_signed_response_alg":"RS256" 
                }
            """.trimIndent().trimMargin()
            val clientMetaDataDecoded = json.decodeFromString<UnvalidatedClientMetaData>(clientMetadataStr)
            val clientMetadataValidated = ClientMetadataValidator(
                walletConfigWithSignAndEncryptionAlgorithms,
                DefaultHttpClientFactory,
            ).validate(clientMetaDataDecoded, responseMode)
            val resolvedRequest =
                ResolvedRequestObject.OpenId4VPAuthorization(
                    presentationDefinition = PresentationDefinition(
                        id = Id("pdId"),
                        inputDescriptors = emptyList(),
                    ),
                    clientMetaData = clientMetadataValidated,
                    clientId = "https%3A%2F%2Fclient.example.org%2Fcb",
                    nonce = "0S6_WzA2Mj",
                    responseMode = responseMode,
                    state = State().value,
                )

            val vpTokenConsensus = Consensus.PositiveConsensus.VPTokenConsensus(
                "dummy_vp_token",
                PresentationSubmission(Id("psId"), Id("pdId"), emptyList()),
            )
            val response = AuthorizationResponseBuilder(walletConfig).build(resolvedRequest, vpTokenConsensus)

            val mockEngine = MockEngine { request ->
                assertEquals(HttpMethod.Post, request.method)

                val body = assertIs<FormDataContent>(request.body)
                val joseResponse = body.formData["response"] as String
                val signedJWT = SignedJWT.parse(joseResponse)
                signedJWT.verify(RSASSAVerifier(RSAKey.parse(rsaSigningKey.toJSONObject())))

                assertNotNull(signedJWT)
                assertNotNull(signedJWT.jwtClaimsSet.issuer)
                assertNotNull(signedJWT.jwtClaimsSet.audience)
                assertEquals(signedJWT.jwtClaimsSet.getClaim("vp_token"), "dummy_vp_token")

                respondOk()
            }

            val outcome = DefaultDispatcher(httpClientFactory = { HttpClient(mockEngine) }).dispatch(response)
            assertEquals(
                DispatchOutcome.VerifierResponse.Accepted(null),
                outcome,
            )
        }

        private fun ecdhDecrypt(ecPrivateKey: ECPrivateKey, jwtString: String): JWTClaimsSet {
            val jwt = EncryptedJWT.parse(jwtString)
            val rsaDecrypter = ECDHDecrypter(ecPrivateKey)
            jwt.decrypt(rsaDecrypter)
            return jwt.jwtClaimsSet
        }
    }

    @Nested
    @DisplayName("In query response")
    inner class QueryResponse {

        private val dispatcher = DefaultDispatcher(httpClientFactory = { error("Not used") })
        private val redirectUriBase = URI("https://foo.bar")

        @Test
        fun `when no consensus, redirect_uri must contain an error query parameter`() = runTest {
            val state = State().value
            val data = AuthorizationResponsePayload.NoConsensusResponseData(state, "client_id")
            val response = AuthorizationResponse.Query(redirectUri = redirectUriBase, data = data)
            testQueryResponse(data, response) {
                assertEquals(
                    AuthorizationRequestErrorCode.USER_CANCELLED.code,
                    getQueryParameter("error"),
                )
            }
        }

        @Test
        fun `when invalid request, redirect_uri must contain an error query parameter`() = runTest {
            val state = State().value
            val error = RequestValidationError.MissingNonce
            val data = AuthorizationResponsePayload.InvalidRequest(error, state, "client_id")
            val expectedErrorCode = AuthorizationRequestErrorCode.fromError(error)
            val response = AuthorizationResponse.Query(redirectUri = redirectUriBase, data = data)
            testQueryResponse(data, response) {
                assertEquals(expectedErrorCode.code, getQueryParameter("error"))
            }
        }

        @Test
        fun `when response for SIOPAuthentication, redirect_uri must contain an id_token query parameter`() = runTest {
            val state = State().value
            val dummyJwt = "dummy"
            val data = AuthorizationResponsePayload.SiopAuthentication(dummyJwt, state, "client_id")
            val response = AuthorizationResponse.Query(redirectUri = redirectUriBase, data = data)
            testQueryResponse(data, response) {
                assertEquals(dummyJwt, getQueryParameter("id_token"))
            }
        }

        @Test
        fun `when response mode is query_jwt, redirect_uri must contain a 'response' and a 'state' query parameter`() =
            runTest {
                val state = State().value
                val dummyJwt = "dummy"
                val data = AuthorizationResponsePayload.SiopAuthentication(dummyJwt, state, "client_id")
                val jarmSpec = JarmSpec(
                    holderId = "DID:example:123",
                    jarmOption = JarmOption.SignedResponse(
                        responseSigningAlg = JWSAlgorithm.RS256,
                        responseSigner = DelegatingResponseSigner(rsaSigningKey, JWSAlgorithm.parse("RS256")),
                    ),
                )
                val response =
                    AuthorizationResponse.QueryJwt(redirectUri = redirectUriBase, data = data, jarmSpec = jarmSpec)
                testQueryResponse(data, response) {
                    assertNotNull(getQueryParameter("response"))
                    assertNotNull(getQueryParameter("state"))
                    val signedJWT = SignedJWT.parse(getQueryParameter("response"))
                    signedJWT.verify(RSASSAVerifier(rsaSigningKey))
                    assertEquals(signedJWT.state, JWSObject.State.VERIFIED)
                    assertNotNull(signedJWT.jwtClaimsSet.getClaim("state"))
                    assertNotNull(signedJWT.jwtClaimsSet.getClaim("id_token"))
                    assertEquals(dummyJwt, signedJWT.jwtClaimsSet.getClaim("id_token"))
                }
            }

        private fun testQueryResponse(
            data: AuthorizationResponsePayload,
            response: AuthorizationResponse.RedirectResponse,
            assertions: Uri.() -> Unit,
        ) = runTest {
            val dispatchOutcome = dispatcher.dispatch(response)
            assertTrue(dispatchOutcome is DispatchOutcome.RedirectURI)
            val redirectUri = (dispatchOutcome).value.toUri()
                .also { println(it) }
                .also(assertions)
            assertEquals(data.state, redirectUri.getQueryParameter("state"))
        }
    }

    @Nested
    @DisplayName("In fragment response")
    inner class FragmentResponse {

        private val dispatcher = DefaultDispatcher(httpClientFactory = { error("Not used") })
        private val redirectUriBase = URI("https://foo.bar")

        @Test
        fun `when no consensus, fragment must contain an error`() = runTest {
            val state = State().value
            val data = AuthorizationResponsePayload.NoConsensusResponseData(state, "client_id")
            val response = AuthorizationResponse.Fragment(redirectUri = redirectUriBase, data = data)
            testFragmentResponse(data, response) { fragmentData ->
                assertEquals(AuthorizationRequestErrorCode.USER_CANCELLED.code, fragmentData["error"])
            }
        }

        @Test
        fun `when invalid request, fragment must contain an error`() = runTest {
            val state = State().value
            val error = RequestValidationError.MissingNonce
            val data = AuthorizationResponsePayload.InvalidRequest(error, state, "client_id")
            val expectedErrorCode = AuthorizationRequestErrorCode.fromError(error)
            val response = AuthorizationResponse.Fragment(redirectUri = redirectUriBase, data = data)
            testFragmentResponse(data, response) { fragmentData ->
                assertEquals(expectedErrorCode.code, fragmentData["error"])
            }
        }

        @Test
        fun `when SIOPAuthentication, fragment must contain an id_token`() = runTest {
            val state = State().value
            val dummyJwt = "dummy"
            val data = AuthorizationResponsePayload.SiopAuthentication(dummyJwt, state, "client_id")
            val response = AuthorizationResponse.Fragment(redirectUri = redirectUriBase, data = data)
            testFragmentResponse(data, response) { fragmentData ->
                assertEquals(dummyJwt, fragmentData["id_token"])
            }
        }

        @Test
        fun `when response mode is query_jwt, redirect_uri must contain a 'response' and a 'state' query parameter`() =
            runTest {
                val state = State().value
                val dummyJwt = "dummy"
                val data = AuthorizationResponsePayload.SiopAuthentication(dummyJwt, state, "client_id")
                val jarmSpec = JarmSpec(
                    holderId = "DID:example:123",
                    jarmOption = JarmOption.SignedResponse(
                        responseSigningAlg = JWSAlgorithm.RS256,
                        responseSigner = DelegatingResponseSigner(rsaSigningKey, JWSAlgorithm.parse("RS256")),
                    ),
                )
                val response =
                    AuthorizationResponse.FragmentJwt(redirectUri = redirectUriBase, data = data, jarmSpec = jarmSpec)
                testFragmentResponse(data, response) { fragmentData ->
                    assertNotNull(fragmentData["state"])
                    assertNotNull(fragmentData["response"])
                    val signedJWT = SignedJWT.parse(fragmentData["response"])
                    signedJWT.verify(RSASSAVerifier(rsaSigningKey))
                    assertEquals(JWSObject.State.VERIFIED, signedJWT.state)
                    assertNotNull(signedJWT.jwtClaimsSet.getClaim("state"))
                    assertNotNull(signedJWT.jwtClaimsSet.getClaim("id_token"))
                    assertEquals(dummyJwt, signedJWT.jwtClaimsSet.getClaim("id_token"))
                }
            }

        private fun testFragmentResponse(
            data: AuthorizationResponsePayload,
            response: AuthorizationResponse.RedirectResponse,
            assertions: (Map<String, String>) -> Unit,
        ) = runTest {
            val dispatchOutcome = dispatcher.dispatch(response)
            assertTrue(dispatchOutcome is DispatchOutcome.RedirectURI)
            val redirectUri = dispatchOutcome.value.toUri()
                .also { println(it) }

            assertNotNull(redirectUri.fragment)
            val map = redirectUri.fragment!!.parseUrlEncodedParameters().toMap().mapValues { it.value.first() }
            map.also(assertions)
            assertEquals(data.state, map["state"])
        }
    }
}
