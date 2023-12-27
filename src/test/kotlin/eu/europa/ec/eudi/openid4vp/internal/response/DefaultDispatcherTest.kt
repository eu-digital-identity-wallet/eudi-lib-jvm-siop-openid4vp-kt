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
package eu.europa.ec.eudi.openid4vp.internal.response

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
import eu.europa.ec.eudi.openid4vp.internal.request.ClientMetaDataValidator
import eu.europa.ec.eudi.openid4vp.internal.request.UnvalidatedClientMetaData
import eu.europa.ec.eudi.openid4vp.internal.request.asURL
import eu.europa.ec.eudi.openid4vp.internal.request.jarmOption
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

    private val walletJarmSingingKeyPair = RSAKeyGenerator(2048)
        .keyUse(KeyUse.SIGNATURE)
        .keyID(UUID.randomUUID().toString())
        .issueTime(Date(System.currentTimeMillis()))
        .generate()

    private val walletJarmSigner: AuthorizationResponseSigner by lazy {
        DelegatingResponseSigner(walletJarmSingingKeyPair, JWSAlgorithm.RS256)
    }

    private val verifierJarmEncryptionKeyPair = ECKeyGenerator(Curve.P_256)
        .keyUse(KeyUse.ENCRYPTION)
        .algorithm(JWEAlgorithm.ECDH_ES)
        .keyID("123")
        .generate()

    private val clientId = "https://client.example.org"

    private val holderId = "DID:example:12341512#$"

    private val clientMetadataStrSigningEncryption = """
            { 
                "jwks": { "keys": [${verifierJarmEncryptionKeyPair.toPublicJWK().toJSONString()} ]},                 
                "subject_syntax_types_supported": [ "urn:ietf:params:oauth:jwk-thumbprint", "did:example", "did:key" ],                
                "authorization_signed_response_alg":"${walletJarmSigner.supportedJWSAlgorithms().first().name}",
                "authorization_encrypted_response_alg":"${verifierJarmEncryptionKeyPair.algorithm.name}", 
                "authorization_encrypted_response_enc":"A256GCM"
            }       
    """.trimIndent().trimMargin()

    val clientMetadataEncryptionOnly = """
               { 
                  "jwks": { "keys": [${verifierJarmEncryptionKeyPair.toPublicJWK().toJSONString()} ]},
                  "subject_syntax_types_supported": [ "urn:ietf:params:oauth:jwk-thumbprint", "did:example", "did:key" ],
                  "authorization_encrypted_response_alg":"${verifierJarmEncryptionKeyPair.algorithm.name}", 
                  "authorization_encrypted_response_enc":"A256GCM"
               }
    """.trimIndent()

    val clientMetadataStrSigning = """
                { 
                    "jwks": { "keys": [${verifierJarmEncryptionKeyPair.toPublicJWK().toJSONString()} ]},
                    "subject_syntax_types_supported": [ "urn:ietf:params:oauth:jwk-thumbprint", "did:example", "did:key" ],
                    "authorization_signed_response_alg": "${walletJarmSigner.supportedJWSAlgorithms().first().name}" 
                }
    """.trimIndent().trimMargin()

    @Nested
    @DisplayName("Encrypted/Signed response")
    inner class DirectPostJwtResponse {

        private val json: Json by lazy { Json { ignoreUnknownKeys = true } }
        private val walletConfig = SiopOpenId4VPConfig(
            supportedClientIdSchemes = listOf(SupportedClientIdScheme.X509SanDns { _ -> true }),
            jarmConfiguration = JarmConfiguration.Signing(
                holderId = holderId,
                supportedAlgorithms = walletJarmSigner.supportedJWSAlgorithms().toList(),
            ),
        )

        private val walletConfigWithSignAndEncryptionAlgorithms = SiopOpenId4VPConfig(
            supportedClientIdSchemes = listOf(SupportedClientIdScheme.X509SanDns { _ -> true }),
            jarmConfiguration = JarmConfiguration.SigningAndEncryption(
                holderId = holderId,
                supportedSigningAlgorithms = walletJarmSigner.supportedJWSAlgorithms().toList(),
                supportedEncryptionAlgorithms = listOf(verifierJarmEncryptionKeyPair.algorithm as JWEAlgorithm),
                supportedEncryptionMethods = listOf(EncryptionMethod.A256GCM),
            ),
        )

        @Test
        fun `client metadata does not match with wallet's supported algorithms`(): Unit = runTest {
            val clientMetaDataDecoded =
                json.decodeFromString<UnvalidatedClientMetaData>(clientMetadataStrSigningEncryption)
            val responseMode = ResponseMode.QueryJwt(URI.create("foo://bar"))
            val clientMetaData = ClientMetaDataValidator(DefaultHttpClientFactory)
                .validate(clientMetaDataDecoded, responseMode)

            val exception = assertThrows<AuthorizationRequestException> { clientMetaData.jarmOption(walletConfig) }
            assertIs<RequestValidationError.UnsupportedClientMetaData>(exception.error)
        }

        @Test
        fun `if response type direct_post jwt, JWE should be returned if only encryption info specified`() = runTest {
            val responseMode = ResponseMode.DirectPostJwt("https://respond.here".asURL().getOrThrow())
            val clientMetaDataDecoded = json.decodeFromString<UnvalidatedClientMetaData>(clientMetadataEncryptionOnly)
            val resolvedRequest =
                resolvedRequestObject(clientMetaDataDecoded, responseMode, walletConfigWithSignAndEncryptionAlgorithms)
            val vpTokenConsensus = Consensus.PositiveConsensus.VPTokenConsensus(
                "dummy_vp_token",
                PresentationSubmission(Id("psId"), Id("pdId"), emptyList()),
            )
            val mockEngine = MockEngine { request ->
                assertEquals(HttpMethod.Post, request.method)
                val body = assertIs<FormDataContent>(request.body)
                val joseResponse = body.formData["response"] as String
                val decryptedJWT = ecdhDecrypt(verifierJarmEncryptionKeyPair.toECPrivateKey(), joseResponse)
                assertEquals(vpTokenConsensus.vpToken, decryptedJWT.getClaim("vp_token"))
                respondOk()
            }

            val expectedOutcome = DispatchOutcome.VerifierResponse.Accepted(null)
            val outcome = DefaultDispatcher(
                httpClientFactory = { HttpClient(mockEngine) },
                holderId = holderId,
                signer = walletJarmSigner,
            ).dispatch(resolvedRequest, vpTokenConsensus)
            assertEquals(expectedOutcome, outcome)
        }

        @Test
        fun `if response type direct_post jwt, JWT should be returned if only signing alg specified`(): Unit = runTest {
            val responseMode = ResponseMode.DirectPostJwt("https://respond.here".asURL().getOrThrow())
            val clientMetaDataDecoded =
                json.decodeFromString<UnvalidatedClientMetaData>(clientMetadataStrSigningEncryption)
            val resolvedRequest =
                resolvedRequestObject(clientMetaDataDecoded, responseMode, walletConfigWithSignAndEncryptionAlgorithms)
            val vpTokenConsensus = Consensus.PositiveConsensus.VPTokenConsensus(
                "dummy_vp_token",
                PresentationSubmission(Id("psId"), Id("pdId"), emptyList()),
            )

            val mockEngine = MockEngine { request ->
                assertEquals(HttpMethod.Post, request.method)

                val body = assertIs<FormDataContent>(request.body)
                val joseResponse = body.formData["response"] as String
                val encrypted = EncryptedJWT.parse(joseResponse)
                val rsaDecrypter = ECDHDecrypter(verifierJarmEncryptionKeyPair.toECPrivateKey())

                encrypted.decrypt(rsaDecrypter)
                assertEquals(JWEObject.State.DECRYPTED, encrypted.state)

                val signedJWT = encrypted.payload.toSignedJWT()
                signedJWT.verify(RSASSAVerifier(RSAKey.parse(walletJarmSingingKeyPair.toJSONObject())))
                assertEquals(JWSObject.State.VERIFIED, signedJWT.state)

                assertTrue("Claim 'aud' must be provided and be equal to holder id") {
                    signedJWT.jwtClaimsSet.getClaim("iss") != null &&
                        signedJWT.jwtClaimsSet.getStringClaim("iss") == walletConfig.holderId()
                }
                assertTrue("Claim 'aud' must be provided and be equal to client_id") {
                    signedJWT.jwtClaimsSet.getClaim("aud") != null &&
                        signedJWT.jwtClaimsSet.getListClaim("aud")[0] == clientId
                }
                assertEquals(signedJWT.jwtClaimsSet.getClaim("vp_token"), "dummy_vp_token")

                respondOk()
            }

            val outcome = DefaultDispatcher(
                httpClientFactory = { HttpClient(mockEngine) },
                holderId = holderId,
                signer = walletJarmSigner,
            ).dispatch(resolvedRequest, vpTokenConsensus)
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
                val clientMetaDataDecoded =
                    json.decodeFromString<UnvalidatedClientMetaData>(clientMetadataStrSigningEncryption)
                val resolvedRequest = resolvedRequestObject(
                    clientMetaDataDecoded,
                    responseMode,
                    walletConfigWithSignAndEncryptionAlgorithms
                )
                val vpTokenConsensus = Consensus.PositiveConsensus.VPTokenConsensus(
                    "dummy_vp_token",
                    PresentationSubmission(Id("psId"), Id("pdId"), emptyList()),
                )


                val mockEngine = MockEngine { request ->
                    assertEquals(HttpMethod.Post, request.method)

                    val body = assertIs<FormDataContent>(request.body)
                    val joseResponse = body.formData["response"] as String
                    val encrypted = EncryptedJWT.parse(joseResponse)
                    val rsaDecrypter = ECDHDecrypter(verifierJarmEncryptionKeyPair.toECPrivateKey())

                    encrypted.decrypt(rsaDecrypter)
                    assertEquals(JWEObject.State.DECRYPTED, encrypted.state)

                    val signedJWT = encrypted.payload.toSignedJWT()
                    signedJWT.verify(RSASSAVerifier(RSAKey.parse(walletJarmSingingKeyPair.toJSONObject())))
                    assertEquals(JWSObject.State.VERIFIED, signedJWT.state)

                    val jwtClaimsSet = signedJWT.jwtClaimsSet
                    assertEquals(walletConfig.holderId(), jwtClaimsSet.issuer)
                    assertContains(jwtClaimsSet.audience, clientId)
                    assertEquals(vpTokenConsensus.vpToken, jwtClaimsSet.getClaim("vp_token") )
                    respondOk()
                }

                val outcome = DefaultDispatcher(
                    httpClientFactory = { HttpClient(mockEngine) },
                    holderId = holderId,
                    signer = walletJarmSigner
                ).dispatch(resolvedRequest, vpTokenConsensus)
                assertEquals(
                    DispatchOutcome.VerifierResponse.Accepted(null),
                    outcome
                )
            }

        @Test
        fun `if enc and sign algs specified, JWE should be returned with signed JWT as encrypted payload`() = runTest {
            val responseMode = ResponseMode.DirectPostJwt("https://respond.here".asURL().getOrThrow())
            val clientMetaDataDecoded = json.decodeFromString<UnvalidatedClientMetaData>(clientMetadataStrSigning)
            val resolvedRequest = resolvedRequestObject(clientMetaDataDecoded, responseMode, walletConfig)
            val vpTokenConsensus = Consensus.PositiveConsensus.VPTokenConsensus(
                vpToken = "dummy_vp_token",
                presentationSubmission = PresentationSubmission(Id("psId"), Id("pdId"), emptyList()),
            )

            val mockEngine = MockEngine { request ->
                assertEquals(HttpMethod.Post, request.method)
                val body = assertIs<FormDataContent>(request.body)
                val joseResponse = body.formData["response"] as String
                val signedJWT = SignedJWT.parse(joseResponse)
                signedJWT.verify(RSASSAVerifier(RSAKey.parse(walletJarmSingingKeyPair.toJSONObject())))
                assertEquals(JWSObject.State.VERIFIED, signedJWT.state)

                assertEquals(walletConfig.holderId(), signedJWT.jwtClaimsSet.issuer)
                assertContains(signedJWT.jwtClaimsSet.audience, clientId)
                assertEquals(vpTokenConsensus.vpToken, signedJWT.jwtClaimsSet.getClaim("vp_token"))
                respondOk()
            }

            val outcome = DefaultDispatcher(
                httpClientFactory = { HttpClient(mockEngine) },
                holderId = holderId,
                signer = walletJarmSigner,
            ).dispatch(resolvedRequest, vpTokenConsensus)
            assertEquals(
                DispatchOutcome.VerifierResponse.Accepted(null),
                outcome,
            )
        }

        private suspend fun resolvedRequestObject(
            unvalidatedClientMetaData: UnvalidatedClientMetaData,
            responseMode: ResponseMode.DirectPostJwt,
            walletConfig: SiopOpenId4VPConfig,
        ): ResolvedRequestObject.OpenId4VPAuthorization {
            val clientMetadataValidated = ClientMetaDataValidator(
                DefaultHttpClientFactory,
            ).validate(unvalidatedClientMetaData, responseMode)

            return ResolvedRequestObject.OpenId4VPAuthorization(
                presentationDefinition = PresentationDefinition(
                    id = Id("pdId"),
                    inputDescriptors = emptyList(),
                ),
                jarmOption = clientMetadataValidated.jarmOption(walletConfig),
                clientId = clientId,
                nonce = "0S6_WzA2Mj",
                responseMode = responseMode,
                state = State().value,
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

        private val redirectUriBase = URI("https://foo.bar")

        @Test
        fun `when no consensus, redirect_uri must contain an error query parameter`() {
            val data = AuthorizationResponsePayload.NoConsensusResponseData(State().value, "client_id")
            val response = AuthorizationResponse.Query(redirectUri = redirectUriBase, data = data)
            response.encodeRedirectURI().assertQueryURIContainsStateAnd(data.state) {
                assertEquals(
                    AuthorizationRequestErrorCode.USER_CANCELLED.code,
                    getQueryParameter("error"),
                )
            }
        }

        @Test
        fun `when invalid request, redirect_uri must contain an error query parameter`() {
            val data = AuthorizationResponsePayload.InvalidRequest(
                RequestValidationError.MissingNonce,
                State().value,
                "client_id",
            )
            val response = AuthorizationResponse.Query(redirectUri = redirectUriBase, data = data)
            response.encodeRedirectURI().assertQueryURIContainsStateAnd(data.state) {
                val expectedErrorCode = AuthorizationRequestErrorCode.fromError(data.error)
                assertEquals(expectedErrorCode.code, getQueryParameter("error"))
            }
        }

        @Test
        fun `when response for SIOPAuthentication, redirect_uri must contain an id_token query parameter`() {
            val data = AuthorizationResponsePayload.SiopAuthentication("dummy", State().value, "client_id")
            val response = AuthorizationResponse.Query(redirectUri = redirectUriBase, data = data)
            response.encodeRedirectURI().assertQueryURIContainsStateAnd(data.state) {
                assertEquals(data.idToken, getQueryParameter("id_token"))
            }
        }

        @Test
        fun `when response mode is query_jwt, redirect_uri must contain a 'response' and a 'state' query parameter`() {
            val data = AuthorizationResponsePayload.SiopAuthentication(
                "dummy",
                State().value,
                "client_id",
            )
            val response = AuthorizationResponse.QueryJwt(
                redirectUri = redirectUriBase,
                data = data,
                jarmOption = JarmOption.SignedResponse(
                    responseSigningAlg = JWSAlgorithm.RS256,
                ),
            )
            response.encodeRedirectURI(holderId, walletJarmSigner).assertQueryURIContainsStateAnd(data.state) {
                assertNotNull(getQueryParameter("response"))

                val signedJWT = SignedJWT.parse(getQueryParameter("response"))
                signedJWT.verify(RSASSAVerifier(walletJarmSingingKeyPair))
                assertEquals(signedJWT.state, JWSObject.State.VERIFIED)

                val jwtClaimsSet = signedJWT.jwtClaimsSet
                assertEquals(data.state, jwtClaimsSet.getClaim("state"))
                assertEquals(data.idToken, jwtClaimsSet.getClaim("id_token"))
            }
        }

        private fun URI.assertQueryURIContainsStateAnd(expectedState: String, assertions: Uri.() -> Unit) {
            val redirectUri = toUri().also(assertions)
            assertEquals(expectedState, redirectUri.getQueryParameter("state"))
        }
    }

    @Nested
    @DisplayName("In fragment response")
    inner class FragmentResponse {

        private val redirectUriBase = URI("https://foo.bar")

        @Test
        fun `when no consensus, fragment must contain an error`() {
            val data = AuthorizationResponsePayload.NoConsensusResponseData(genState(), "client_id")
            val response = AuthorizationResponse.Fragment(redirectUri = redirectUriBase, data = data)

            response.encodeRedirectURI().assertFragmentURIContainsStateAnd(data.state) { fragmentData ->
                assertEquals(AuthorizationRequestErrorCode.USER_CANCELLED.code, fragmentData["error"])
            }
        }

        @Test
        fun `when invalid request, fragment must contain an error`() {
            val data = AuthorizationResponsePayload.InvalidRequest(
                RequestValidationError.MissingNonce,
                genState(),
                "client_id",
            )
            val response = AuthorizationResponse.Fragment(redirectUri = redirectUriBase, data = data)

            response.encodeRedirectURI().assertFragmentURIContainsStateAnd(data.state) { fragmentData ->
                val expectedErrorCode = AuthorizationRequestErrorCode.fromError(data.error)
                assertEquals(expectedErrorCode.code, fragmentData["error"])
            }
        }

        @Test
        fun `when SIOPAuthentication, fragment must contain an id_token`() {
            val data = AuthorizationResponsePayload.SiopAuthentication("dummy", genState(), "client_id")
            val response = AuthorizationResponse.Fragment(redirectUri = redirectUriBase, data = data)
            response.encodeRedirectURI().assertFragmentURIContainsStateAnd(data.state) { fragmentData ->
                assertEquals(data.idToken, fragmentData["id_token"])
            }
        }

        @Test
        fun `when response mode is query_jwt, redirect_uri must contain a 'response' and a 'state' query parameter`() {
            val data = AuthorizationResponsePayload.SiopAuthentication("dummy", genState(), "client_id")
            val response =
                AuthorizationResponse.FragmentJwt(
                    redirectUri = redirectUriBase,
                    data = data,
                    jarmOption = JarmOption.SignedResponse(JWSAlgorithm.RS256),
                )
            response.encodeRedirectURI(holderId, walletJarmSigner)
                .assertFragmentURIContainsStateAnd(data.state) { fragmentData ->
                    assertEquals(data.state, fragmentData["state"])
                    assertNotNull(fragmentData["response"])

                    val signedJWT = SignedJWT.parse(fragmentData["response"])
                    signedJWT.verify(RSASSAVerifier(walletJarmSingingKeyPair))
                    assertEquals(JWSObject.State.VERIFIED, signedJWT.state)

                    val jwtClaimsSet = signedJWT.jwtClaimsSet
                    assertEquals(data.state, jwtClaimsSet.getClaim("state"))
                    assertEquals(data.idToken, jwtClaimsSet.getClaim("id_token"))
                }
        }

        private fun URI.assertFragmentURIContainsStateAnd(
            expectedState: String,
            assertions: (Map<String, String>) -> Unit,
        ) {
            val redirectUri = toUri().also { println(it) }
            assertNotNull(redirectUri.fragment)
            val map = redirectUri.fragment!!.parseUrlEncodedParameters().toMap().mapValues { it.value.first() }
            map.also(assertions)
            assertEquals(expectedState, map["state"])
        }
    }
}

private fun genState(): String = State().value
