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
import com.nimbusds.jose.EncryptionMethod
import com.nimbusds.jose.JWEAlgorithm
import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.crypto.ECDHDecrypter
import com.nimbusds.jose.crypto.RSASSAVerifier
import com.nimbusds.jose.jwk.*
import com.nimbusds.jose.jwk.gen.ECKeyGenerator
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator
import com.nimbusds.jwt.EncryptedJWT
import com.nimbusds.jwt.JWTClaimsSet
import com.nimbusds.jwt.SignedJWT
import com.nimbusds.oauth2.sdk.id.State
import eu.europa.ec.eudi.openid4vp.*
import eu.europa.ec.eudi.openid4vp.RequestValidationError.MissingNonce
import eu.europa.ec.eudi.openid4vp.internal.request.ClientMetaDataValidator
import eu.europa.ec.eudi.openid4vp.internal.request.UnvalidatedClientMetaData
import eu.europa.ec.eudi.openid4vp.internal.request.asURL
import eu.europa.ec.eudi.openid4vp.internal.request.jarmOption
import eu.europa.ec.eudi.openid4vp.internal.response.DefaultDispatcherTest.Verifier.assertIsJwtEncryptedWithVerifiersPubKey
import eu.europa.ec.eudi.openid4vp.internal.response.DefaultDispatcherTest.Wallet.assertIsJwtSignedByWallet
import eu.europa.ec.eudi.openid4vp.internal.response.DefaultDispatcherTest.Wallet.assertIsSignedByWallet
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
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.jsonObject
import org.junit.jupiter.api.DisplayName
import org.junit.jupiter.api.Nested
import org.junit.jupiter.api.assertDoesNotThrow
import org.junit.jupiter.api.assertThrows
import java.net.URI
import java.util.*
import kotlin.test.*

class DefaultDispatcherTest {

    //
    // Verifier settings
    //

    internal object Verifier {

        const val CLIENT_ID = "https://client.example.org"

        val jarmEncryptionKeyPair: ECKey = ECKeyGenerator(Curve.P_256)
            .keyUse(KeyUse.ENCRYPTION)
            .algorithm(JWEAlgorithm.ECDH_ES)
            .keyID("123")
            .generate()

        val metaDataRequestingEncryptedResponse = UnvalidatedClientMetaData(
            jwks = JWKSet(jarmEncryptionKeyPair).toJsonObject(true),
            authorizationEncryptedResponseAlg = jarmEncryptionKeyPair.algorithm.name,
            authorizationEncryptedResponseEnc = EncryptionMethod.A256GCM.name,
        )

        val metaDataRequestingSignedAndEncryptedResponse = metaDataRequestingEncryptedResponse.copy(
            authorizationSignedResponseAlg = JWSAlgorithm.RS256.name,
        )

        private fun JWKSet.toJsonObject(publicKeysOnly: Boolean = true): JsonObject =
            Json.parseToJsonElement(this.toString(publicKeysOnly)).jsonObject

        fun String.assertIsJwtEncryptedWithVerifiersPubKey(): EncryptedJWT {
            val jwt = assertDoesNotThrow { EncryptedJWT.parse(this) }
            val rsaDecrypter = ECDHDecrypter(jarmEncryptionKeyPair)
            jwt.decrypt(rsaDecrypter)
            return jwt
        }
    }

    //
    // Wallet settings
    //

    private object Wallet {

        private val jarmSigningKeyPair: RSAKey by lazy {
            RSAKeyGenerator(2048)
                .keyUse(KeyUse.SIGNATURE)
                .keyID(UUID.randomUUID().toString())
                .issueTime(Date(System.currentTimeMillis()))
                .generate()
        }

        val jarmSigner: AuthorizationResponseSigner by lazy {
            DelegatingResponseSigner(jarmSigningKeyPair, JWSAlgorithm.RS256)
        }

        val config = SiopOpenId4VPConfig(
            supportedClientIdSchemes = listOf(SupportedClientIdScheme.X509SanDns { _ -> true }),
            jarmConfiguration = JarmConfiguration.SigningAndEncryption(
                holderId = "DID:example:12341512#$",
                supportedSigningAlgorithms = jarmSigner.supportedJWSAlgorithms().toList(),
                supportedEncryptionAlgorithms = listOf(Verifier.jarmEncryptionKeyPair.algorithm as JWEAlgorithm),
                supportedEncryptionMethods = listOf(EncryptionMethod.A256GCM),
            ),
        )

        /**
         * Creates a [Dispatcher] that mocks the behavior of a Verifier, in case of posting
         * an authorization response (direct post, or direct post jwt response_mode).
         *
         * The verifier asserts that it receives an HTTP Post, which contains [FormDataContent], having
         * a parameter named `response`
         *
         * @param responseParameterAssertions assertions applicable to the content of the form parameter
         * `response`
         */
        fun createDispatcherWithVerifierAsserting(responseParameterAssertions: (String) -> Unit): Dispatcher {
            val mockEngine = MockEngine { request ->
                assertEquals(HttpMethod.Post, request.method)
                val body = assertIs<FormDataContent>(request.body)
                val responseParameter = body.formData["response"] as String
                responseParameterAssertions(responseParameter)
                respondOk()
            }
            return DefaultDispatcher(
                httpClientFactory = { HttpClient(mockEngine) },
                holderId = config.holderId(),
                signer = jarmSigner,
            )
        }

        val clientMetaDataValidator = ClientMetaDataValidator(DefaultHttpClientFactory)

        fun String.assertIsJwtSignedByWallet(): JWTClaimsSet {
            val signedJWT = SignedJWT.parse(this)
            return signedJWT.assertIsSignedByWallet()
        }

        fun SignedJWT.assertIsSignedByWallet(): JWTClaimsSet {
            val isSigned = verify(RSASSAVerifier(jarmSigningKeyPair))
            assertTrue { isSigned }
            return jwtClaimsSet
        }
    }

    @Nested
    @DisplayName("Encrypted/Signed response")
    inner class DirectPostJwtResponse {

        @Test
        fun `client metadata does not match with wallet's supported algorithms`(): Unit = runTest {
            val clientMetaData = Wallet.clientMetaDataValidator.validate(
                Verifier.metaDataRequestingSignedAndEncryptedResponse,
                ResponseMode.QueryJwt(URI.create("foo://bar")),
            )

            val exception = assertThrows<AuthorizationRequestException> {
                clientMetaData.jarmOption(JarmConfiguration.NotSupported)
            }
            assertIs<RequestValidationError.UnsupportedClientMetaData>(exception.error)
        }

        @Test
        fun `if response type direct_post jwt, JWE should be returned if only encryption info specified`() = runTest {
            val verifierRequest = createOpenId4VPRequest(
                Verifier.metaDataRequestingEncryptedResponse,
                ResponseMode.DirectPostJwt("https://respond.here".asURL().getOrThrow()),
            )
            val vpTokenConsensus = Consensus.PositiveConsensus.VPTokenConsensus(
                "dummy_vp_token",
                PresentationSubmission(Id("psId"), Id("pdId"), emptyList()),
            )

            val dispatcher = Wallet.createDispatcherWithVerifierAsserting { responseParam ->
                val encryptedJwt = responseParam.assertIsJwtEncryptedWithVerifiersPubKey()
                val jwtClaimSet = encryptedJwt.jwtClaimsSet
                assertEquals(vpTokenConsensus.vpToken, jwtClaimSet.getClaim("vp_token"))
            }

            val outcome = dispatcher.dispatch(verifierRequest, vpTokenConsensus)
            val expectedOutcome = DispatchOutcome.VerifierResponse.Accepted(null)
            assertEquals(expectedOutcome, outcome)
        }

        @Test
        fun `if response type direct_post jwt, JWT should be returned if only signing alg specified`(): Unit = runTest {
            val verifiersRequest = createOpenId4VPRequest(
                Verifier.metaDataRequestingSignedAndEncryptedResponse,
                ResponseMode.DirectPostJwt("https://respond.here".asURL().getOrThrow()),
            )

            val vpTokenConsensus = Consensus.PositiveConsensus.VPTokenConsensus(
                "dummy_vp_token",
                PresentationSubmission(Id("psId"), Id("pdId"), emptyList()),
            )

            val dispatcher = Wallet.createDispatcherWithVerifierAsserting { responseParam ->
                val encryptedJwt = responseParam.assertIsJwtEncryptedWithVerifiersPubKey()
                val jwtClaimsSet = encryptedJwt.payload.toSignedJWT().assertIsSignedByWallet()
                assertEquals(jwtClaimsSet.issuer, Wallet.config.holderId())
                assertContains(jwtClaimsSet.audience, Verifier.CLIENT_ID)
                assertEquals(vpTokenConsensus.vpToken, jwtClaimsSet.getClaim("vp_token"))
            }
            val outcome = dispatcher.dispatch(verifiersRequest, vpTokenConsensus)
            val expectedOutcome = DispatchOutcome.VerifierResponse.Accepted(null)
            assertEquals(expectedOutcome, outcome)
        }

        @Test
        @Suppress("ktlint")
        fun `if response type direct_post jwt, JWT should be returned if only signing alg, encryption alg and encryption method are specified and supported by wallet`(): Unit =
            runTest {
                val verifiersRequest = createOpenId4VPRequest(
                    Verifier.metaDataRequestingSignedAndEncryptedResponse,
                    ResponseMode.DirectPostJwt("https://respond.here".asURL().getOrThrow()),
                )

                val vpTokenConsensus = Consensus.PositiveConsensus.VPTokenConsensus(
                    "dummy_vp_token",
                    PresentationSubmission(Id("psId"), Id("pdId"), emptyList()),
                )

                val dispatcher = Wallet.createDispatcherWithVerifierAsserting { responseParam ->
                    val encryptedJwt = responseParam.assertIsJwtEncryptedWithVerifiersPubKey()
                    val jwtClaimsSet = encryptedJwt.payload.toSignedJWT().assertIsSignedByWallet()
                    assertEquals(Wallet.config.holderId(), jwtClaimsSet.issuer)
                    assertContains(jwtClaimsSet.audience, Verifier.CLIENT_ID)
                    assertEquals(vpTokenConsensus.vpToken, jwtClaimsSet.getClaim("vp_token"))

                }
                val outcome = dispatcher.dispatch(verifiersRequest, vpTokenConsensus)
                val expected = DispatchOutcome.VerifierResponse.Accepted(null)
                assertEquals(expected, outcome)
            }

        @Test
        fun `if verifier requires signed response, JARM signed JWT should be posted`() = runTest {
            val verifierMetaData = UnvalidatedClientMetaData(
                authorizationSignedResponseAlg = JWSAlgorithm.RS256.name,
            )
            val responseMode = ResponseMode.DirectPostJwt("https://respond.here".asURL().getOrThrow())

            val resolvedRequest = createOpenId4VPRequest(verifierMetaData, responseMode)
            val vpTokenConsensus = Consensus.PositiveConsensus.VPTokenConsensus(
                vpToken = "dummy_vp_token",
                presentationSubmission = PresentationSubmission(Id("psId"), Id("pdId"), emptyList()),
            )

            val dispatcher = Wallet.createDispatcherWithVerifierAsserting { responseParam ->
                val jwtClaimsSet = responseParam.assertIsJwtSignedByWallet()
                assertEquals(Wallet.config.holderId(), jwtClaimsSet.issuer)
                assertContains(jwtClaimsSet.audience, Verifier.CLIENT_ID)
                assertEquals(vpTokenConsensus.vpToken, jwtClaimsSet.getClaim("vp_token"))
            }

            val expectedOutcome = DispatchOutcome.VerifierResponse.Accepted(null)
            val outcome = dispatcher.dispatch(resolvedRequest, vpTokenConsensus)
            assertEquals(expectedOutcome, outcome)
        }

        private suspend fun createOpenId4VPRequest(
            unvalidatedClientMetaData: UnvalidatedClientMetaData,
            responseMode: ResponseMode.DirectPostJwt,
        ): ResolvedRequestObject.OpenId4VPAuthorization {
            val clientMetadataValidated =
                Wallet.clientMetaDataValidator.validate(unvalidatedClientMetaData, responseMode)

            return ResolvedRequestObject.OpenId4VPAuthorization(
                presentationDefinition = PresentationDefinition(
                    id = Id("pdId"),
                    inputDescriptors = emptyList(),
                ),
                jarmOption = clientMetadataValidated.jarmOption(Wallet.config),
                clientId = Verifier.CLIENT_ID,
                nonce = "0S6_WzA2Mj",
                responseMode = responseMode,
                state = genState(),
            )
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
            val data = AuthorizationResponsePayload.InvalidRequest(MissingNonce, genState(), "client_id")
            val response = AuthorizationResponse.Query(redirectUriBase, data)
            val redirectURI = response.encodeRedirectURI()

            redirectURI.assertQueryURIContainsStateAnd(data.state) {
                val expectedErrorCode = AuthorizationRequestErrorCode.fromError(data.error)
                assertEquals(expectedErrorCode.code, getQueryParameter("error"))
            }
        }

        @Test
        fun `when response for SIOPAuthentication, redirect_uri must contain an id_token query parameter`() {
            val data = AuthorizationResponsePayload.SiopAuthentication("dummy", genState(), "client_id")
            val response = AuthorizationResponse.Query(redirectUriBase, data)
            val redirectURI = response.encodeRedirectURI()

            redirectURI.assertQueryURIContainsStateAnd(data.state) {
                assertEquals(data.idToken, getQueryParameter("id_token"))
            }
        }

        @Test
        fun `when response mode is query_jwt, redirect_uri must contain a 'response' and a 'state' query parameter`() {
            val data = AuthorizationResponsePayload.SiopAuthentication("dummy", genState(), "client_id")
            val response = AuthorizationResponse.QueryJwt(
                redirectUriBase,
                data,
                JarmOption.SignedResponse(JWSAlgorithm.RS256),
            )
            val redirectURI = response.encodeRedirectURI(Wallet.config.holderId()!!, Wallet.jarmSigner)

            redirectURI.assertQueryURIContainsStateAnd(data.state) {
                val responseParameter = getQueryParameter("response")
                assertNotNull(responseParameter)
                val jwtClaimsSet = responseParameter.assertIsJwtSignedByWallet()
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
                MissingNonce,
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
            response.encodeRedirectURI(Wallet.config.holderId()!!, Wallet.jarmSigner)
                .assertFragmentURIContainsStateAnd(data.state) { fragmentData ->
                    assertEquals(data.state, fragmentData["state"])
                    val responseParameter = fragmentData["response"]
                    assertNotNull(responseParameter)
                    val jwtClaimsSet = responseParameter.assertIsJwtSignedByWallet()
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
