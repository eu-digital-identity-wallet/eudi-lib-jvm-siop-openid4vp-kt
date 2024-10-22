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
import com.nimbusds.jose.util.Base64URL
import com.nimbusds.jwt.EncryptedJWT
import com.nimbusds.jwt.JWTClaimsSet
import com.nimbusds.jwt.SignedJWT
import com.nimbusds.oauth2.sdk.id.State
import eu.europa.ec.eudi.openid4vp.*
import eu.europa.ec.eudi.openid4vp.RequestValidationError.MissingNonce
import eu.europa.ec.eudi.openid4vp.internal.request.ManagedClientMetaValidator
import eu.europa.ec.eudi.openid4vp.internal.request.UnvalidatedClientMetaData
import eu.europa.ec.eudi.openid4vp.internal.request.asURL
import eu.europa.ec.eudi.openid4vp.internal.request.jarmRequirement
import eu.europa.ec.eudi.openid4vp.internal.response.DefaultDispatcherTest.Verifier.assertIsJwtEncryptedWithVerifiersPubKey
import eu.europa.ec.eudi.openid4vp.internal.response.DefaultDispatcherTest.Wallet.assertIsJwtSignedByWallet
import eu.europa.ec.eudi.openid4vp.internal.response.DefaultDispatcherTest.Wallet.assertIsSignedByWallet
import eu.europa.ec.eudi.prex.Id
import eu.europa.ec.eudi.prex.PresentationDefinition
import eu.europa.ec.eudi.prex.PresentationSubmission
import io.ktor.client.*
import io.ktor.client.engine.mock.*
import io.ktor.client.plugins.contentnegotiation.*
import io.ktor.client.request.forms.*
import io.ktor.http.*
import io.ktor.serialization.kotlinx.json.*
import io.ktor.util.*
import kotlinx.coroutines.test.runTest
import kotlinx.serialization.json.*
import org.junit.jupiter.api.DisplayName
import org.junit.jupiter.api.Nested
import org.junit.jupiter.api.assertDoesNotThrow
import org.junit.jupiter.api.assertThrows
import java.net.URI
import java.time.Clock
import java.util.*
import kotlin.test.*

class DefaultDispatcherTest {

    //
    // Verifier settings
    //

    internal object Verifier {

        val CLIENT = Client.Preregistered("https://client.example.org", "Verifier")

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

        val config = SiopOpenId4VPConfig(
            supportedClientIdSchemes = listOf(SupportedClientIdScheme.X509SanDns.NoValidation),
            jarmConfiguration = JarmConfiguration.SigningAndEncryption(
                signer = JarmSigner(jarmSigningKeyPair),
                supportedEncryptionAlgorithms = listOf(Verifier.jarmEncryptionKeyPair.algorithm as JWEAlgorithm),
                supportedEncryptionMethods = listOf(EncryptionMethod.A256GCM),
            ),
            vpConfiguration = VPConfiguration(
                vpFormats = VpFormats(VpFormat.MsoMdoc, VpFormat.SdJwtVc.ES256),
            ),
            clock = Clock.systemDefaultZone(),
        )

        /**
         * Creates a [Dispatcher] that mocks the behavior of a Verifier, in case of posting
         * an authorization response (direct post, or direct post jwt response_mode).
         *
         * The verifier asserts that it receives an HTTP Post, which contains [FormDataContent], having
         * a parameter named `response`
         *
         * @param responseBodyRedirectUri redirect uri to be included in the generate response body
         * @param responseParameterAssertions assertions applicable to the content of the form parameter
         * `response`
         */
        fun createDispatcherWithVerifierAsserting(
            responseBodyRedirectUri: URI? = null,
            responseParameterAssertions: (String) -> Unit,
        ): Dispatcher {
            val mockEngine = MockEngine { request ->
                assertEquals(HttpMethod.Post, request.method)
                request.body.contentType?.let {
                    assertEquals("application/x-www-form-urlencoded", it.toString())
                }
                request.headers[HttpHeaders.ContentType]?.let {
                    assertEquals("application/x-www-form-urlencoded", it)
                }
                val body = assertIs<FormData>(request.body)
                val responseParameter = body.formData["response"] as String
                responseParameterAssertions(responseParameter)

                val response = buildJsonObject {
                    responseBodyRedirectUri?.let { put("redirect_uri", JsonPrimitive(it.toString())) }
                }.toString()

                respond(
                    response,
                    HttpStatusCode.OK,
                    headers { append(HttpHeaders.ContentType, ContentType.Application.Json) },
                )
            }

            val httpClient = HttpClient(mockEngine) {
                expectSuccess = true
                install(ContentNegotiation) {
                    json()
                }
            }

            return DefaultDispatcher(config) { httpClient }
        }

        val clientMetaDataValidator = ManagedClientMetaValidator(DefaultHttpClientFactory)

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
                JarmConfiguration.NotSupported.jarmRequirement(clientMetaData)
            }
            assertIs<RequestValidationError.UnsupportedClientMetaData>(exception.error)
        }

        @Test
        fun `if response type direct_post jwt, JWE should be returned if only encryption info specified`() = runTest {
            suspend fun test(vpToken: VpToken, redirectUri: URI? = null) {
                val verifierRequest = createOpenId4VPRequest(
                    Verifier.metaDataRequestingEncryptedResponse,
                    ResponseMode.DirectPostJwt("https://respond.here".asURL().getOrThrow()),
                )
                val vpTokenConsensus = Consensus.PositiveConsensus.VPTokenConsensus(
                    vpToken,
                    PresentationSubmission(Id("psId"), Id("pdId"), emptyList()),
                )

                val dispatcher = Wallet.createDispatcherWithVerifierAsserting(redirectUri) { responseParam ->
                    val encryptedJwt = responseParam.assertIsJwtEncryptedWithVerifiersPubKey()

                    if (vpToken.verifiablePresentations.any { it is VerifiablePresentation.MsoMdoc }) {
                        assertEquals(Base64URL.encode(verifierRequest.nonce), encryptedJwt.header.agreementPartyVInfo)
                        assertEquals(vpToken.apu, encryptedJwt.header.agreementPartyUInfo)
                    } else {
                        assertNull(encryptedJwt.header.agreementPartyVInfo)
                        assertNull(encryptedJwt.header.agreementPartyUInfo)
                    }
                    val jwtClaimSet = encryptedJwt.jwtClaimsSet

                    val vpTokenClaim = jwtClaimSet.vpTokenClaim()

                    assertEquals(vpTokenConsensus.vpToken.toJson(), vpTokenClaim)
                }

                val outcome = dispatcher.dispatch(verifierRequest, vpTokenConsensus)
                val expectedOutcome = DispatchOutcome.VerifierResponse.Accepted(redirectUri)
                assertEquals(expectedOutcome, outcome)
            }

            test(VpToken.Generic("dummy_vp_token"))
            test(
                VpToken.MsoMdoc(Base64URL.encode("dummy_apu"), "dummy_vp_token"),
            )
            test(
                VpToken.Generic("dummy_vp_token"),
                redirectUri = URI.create("https://redirect.here"),
            )
            test(
                VpToken.MsoMdoc(Base64URL.encode("dummy_apu"), "dummy_vp_token"),
                redirectUri = URI.create("https://redirect.here"),
            )
        }

        @Test
        fun `if response type direct_post jwt, JWT should be returned if only signing alg specified`(): Unit = runTest {
            suspend fun test(redirectUri: URI? = null) {
                val verifiersRequest = createOpenId4VPRequest(
                    Verifier.metaDataRequestingSignedAndEncryptedResponse,
                    ResponseMode.DirectPostJwt("https://respond.here".asURL().getOrThrow()),
                )

                val vpTokenConsensus = Consensus.PositiveConsensus.VPTokenConsensus(
                    VpToken.Generic("dummy_vp_token"),
                    PresentationSubmission(Id("psId"), Id("pdId"), emptyList()),
                )

                val dispatcher = Wallet.createDispatcherWithVerifierAsserting(redirectUri) { responseParam ->
                    val encryptedJwt = responseParam.assertIsJwtEncryptedWithVerifiersPubKey()
                    assertNull(encryptedJwt.header.agreementPartyVInfo)
                    assertNull(encryptedJwt.header.agreementPartyUInfo)
                    val jwtClaimsSet = encryptedJwt.payload.toSignedJWT().assertIsSignedByWallet()
                    assertEquals(Wallet.config.issuer?.value, jwtClaimsSet.issuer)
                    assertContains(jwtClaimsSet.audience, Verifier.CLIENT.id)
                    assertEquals(vpTokenConsensus.vpToken.toJson(), jwtClaimsSet.vpTokenClaim())
                }
                val outcome = dispatcher.dispatch(verifiersRequest, vpTokenConsensus)
                val expectedOutcome = DispatchOutcome.VerifierResponse.Accepted(redirectUri)
                assertEquals(expectedOutcome, outcome)
            }

            test()
            test(URI.create("https://redirect.here"))
        }

        @Test
        @Suppress("ktlint")
        fun `if response type direct_post jwt, JWT should be returned if only signing alg, encryption alg and encryption method are specified and supported by wallet`(): Unit =
            runTest {
                suspend fun test(redirectUri: URI? = null) {
                    val verifiersRequest = createOpenId4VPRequest(
                        Verifier.metaDataRequestingSignedAndEncryptedResponse,
                        ResponseMode.DirectPostJwt("https://respond.here".asURL().getOrThrow()),
                    )

                    val vpTokenConsensus = Consensus.PositiveConsensus.VPTokenConsensus(
                        VpToken.Generic("dummy_vp_token"),
                        PresentationSubmission(Id("psId"), Id("pdId"), emptyList()),
                    )

                    val dispatcher = Wallet.createDispatcherWithVerifierAsserting(redirectUri) { responseParam ->
                        val encryptedJwt = responseParam.assertIsJwtEncryptedWithVerifiersPubKey()
                        assertNull(encryptedJwt.header.agreementPartyVInfo)
                        assertNull(encryptedJwt.header.agreementPartyUInfo)
                        val jwtClaimsSet = encryptedJwt.payload.toSignedJWT().assertIsSignedByWallet()
                        assertEquals(Wallet.config.issuer?.value, jwtClaimsSet.issuer)
                        assertContains(jwtClaimsSet.audience, Verifier.CLIENT.id)
                        val vpTokenClaim = jwtClaimsSet.vpTokenClaim()
                        val expectedVpToken = vpTokenConsensus.vpToken.toJson()
                        assertEquals(expectedVpToken, vpTokenClaim)

                    }
                    val outcome = dispatcher.dispatch(verifiersRequest, vpTokenConsensus)
                    val expected = DispatchOutcome.VerifierResponse.Accepted(redirectUri)
                    assertEquals(expected, outcome)
                }

                test()
                test(URI.create("https://redirect.here"))
            }

        @Test
        fun `if verifier requires signed response, JARM signed JWT should be posted`() = runTest {
            suspend fun test(redirectUri: URI? = null) {
                val verifierMetaData = UnvalidatedClientMetaData(
                    authorizationSignedResponseAlg = JWSAlgorithm.RS256.name,
                )
                val responseMode = ResponseMode.DirectPostJwt("https://respond.here".asURL().getOrThrow())

                val resolvedRequest = createOpenId4VPRequest(verifierMetaData, responseMode)
                val vpTokenConsensus = Consensus.PositiveConsensus.VPTokenConsensus(
                    vpToken = VpToken.Generic("dummy_vp_token"),
                    presentationSubmission = PresentationSubmission(Id("psId"), Id("pdId"), emptyList()),
                )

                val dispatcher = Wallet.createDispatcherWithVerifierAsserting(redirectUri) { responseParam ->
                    val jwtClaimsSet = responseParam.assertIsJwtSignedByWallet()
                    assertEquals(Wallet.config.issuer?.value, jwtClaimsSet.issuer)
                    assertContains(jwtClaimsSet.audience, Verifier.CLIENT.id)
                    assertNotNull(jwtClaimsSet.expirationTime)
                    assertEquals(vpTokenConsensus.vpToken.toJson(), jwtClaimsSet.vpTokenClaim())
                }

                val expectedOutcome = DispatchOutcome.VerifierResponse.Accepted(redirectUri)
                val outcome = dispatcher.dispatch(resolvedRequest, vpTokenConsensus)
                assertEquals(expectedOutcome, outcome)
            }

            test()
            test(URI.create("https://redirect.here"))
        }

        @Test
        fun `support vp_token with multiple verifiable presentations`() = runTest {
            suspend fun test(vpToken: VpToken, redirectUri: URI? = null) {
                val verifierMetaData = UnvalidatedClientMetaData(
                    authorizationSignedResponseAlg = JWSAlgorithm.RS256.name,
                )
                val responseMode = ResponseMode.DirectPostJwt("https://respond.here".asURL().getOrThrow())

                val resolvedRequest = createOpenId4VPRequest(verifierMetaData, responseMode)
                val vpTokenConsensus = Consensus.PositiveConsensus.VPTokenConsensus(
                    vpToken = vpToken,
                    presentationSubmission = PresentationSubmission(Id("psId"), Id("pdId"), emptyList()),
                )

                val dispatcher = Wallet.createDispatcherWithVerifierAsserting(redirectUri) { responseParam ->
                    val jwtClaimsSet = responseParam.assertIsJwtSignedByWallet()
                    assertEquals(Wallet.config.issuer?.value, jwtClaimsSet.issuer)
                    assertContains(jwtClaimsSet.audience, Verifier.CLIENT.id)
                    assertNotNull(jwtClaimsSet.expirationTime)
                    assertEquals(vpTokenConsensus.vpToken.toJson(), jwtClaimsSet.vpTokenClaim())
                }

                val expectedOutcome = DispatchOutcome.VerifierResponse.Accepted(redirectUri)
                val outcome = dispatcher.dispatch(resolvedRequest, vpTokenConsensus)
                assertEquals(expectedOutcome, outcome)
            }

            test(vpTokenWithMultipleGenericPresentations())
            test(vpTokenWithMultipleGenericPresentations(), URI.create("https://redirect.here"))
            test(vpTokenWithMultipleMsoMdocPresentations(), URI.create("https://redirect.here"))
            test(vpTokenWithMultipleMixedPresentations(), URI.create("https://redirect.here"))
        }

        private fun vpTokenWithMultipleMixedPresentations(): VpToken =
            VpToken(
                verifiablePresentations = listOf(
                    VerifiablePresentation.Generic("dummy_vp_token"),
                    VerifiablePresentation.MsoMdoc("dummy_vp_token"),
                    VerifiablePresentation.JsonObj(
                        buildJsonObject {
                            put("claimString", JsonPrimitive("claim1_value"))
                            put(
                                "claimArray",
                                buildJsonArray {
                                    add(JsonPrimitive("array_value_1"))
                                    add(JsonPrimitive("array_value_2"))
                                    add(JsonPrimitive("array_value_3"))
                                },
                            )
                            put(
                                "claimObject",
                                buildJsonObject {
                                    put("child_json_obj_1", JsonPrimitive("val1"))
                                    put("child_json_obj_2", JsonPrimitive("val2"))
                                },
                            )
                        },
                    ),
                ),
            )

        private fun vpTokenWithMultipleGenericPresentations(): VpToken =
            VpToken.Generic("dummy_vp_token_1", "dummy_vp_token_2", "dummy_vp_token_3")

        private fun vpTokenWithMultipleMsoMdocPresentations(): VpToken =
            VpToken.MsoMdoc(
                Base64URL.encode("dummy_apu"),
                "dummy_msomdoc_vp_token_1",
                "dummy_msomdoc_vp_token_2",
                "dummy_msomdoc_vp_token_3",
            )

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
                jarmRequirement = Wallet.config.jarmRequirement(clientMetadataValidated),
                vpFormats = VpFormats(VpFormat.MsoMdoc),
                client = Verifier.CLIENT,
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
            fun test(state: String? = null, asserter: URI.(Uri.() -> Unit) -> Unit) {
                val data = AuthorizationResponsePayload.NoConsensusResponseData(generateNonce(), state, "client_id")
                val response = AuthorizationResponse.Query(redirectUri = redirectUriBase, data = data)
                response.encodeRedirectURI()
                    .asserter {
                        assertEquals(AuthorizationRequestErrorCode.USER_CANCELLED.code, getQueryParameter("error"))
                    }
            }

            genState().let { state -> test(state) { assertQueryURIContainsStateAnd(state, it) } }
            test { assertQueryURIDoesNotContainStateAnd(it) }
        }

        @Test
        fun `when invalid request, redirect_uri must contain an error query parameter`() {
            fun test(state: String? = null, asserter: URI.(Uri.() -> Unit) -> Unit) {
                val data =
                    AuthorizationResponsePayload.InvalidRequest(MissingNonce, generateNonce(), state, "client_id")
                val response = AuthorizationResponse.Query(redirectUriBase, data)
                val redirectURI = response.encodeRedirectURI()

                redirectURI.asserter {
                    val expectedErrorCode = AuthorizationRequestErrorCode.fromError(data.error)
                    assertEquals(expectedErrorCode.code, getQueryParameter("error"))
                }
            }

            genState().let { state -> test(state) { assertQueryURIContainsStateAnd(state, it) } }
            test { assertQueryURIDoesNotContainStateAnd(it) }
        }

        @Test
        fun `when response for SIOPAuthentication, redirect_uri must contain an id_token query parameter`() {
            fun test(state: String? = null, asserter: URI.(Uri.() -> Unit) -> Unit) {
                val data = AuthorizationResponsePayload.SiopAuthentication("dummy", generateNonce(), state, "client_id")
                val response = AuthorizationResponse.Query(redirectUriBase, data)
                val redirectURI = response.encodeRedirectURI()

                redirectURI.asserter {
                    assertEquals(data.idToken, getQueryParameter("id_token"))
                }
            }

            genState().let { state -> test(state) { assertQueryURIContainsStateAnd(state, it) } }
            test { assertQueryURIDoesNotContainStateAnd(it) }
        }

        @Test
        fun `when response mode is query_jwt, redirect_uri must contain a 'response' and a 'state' query parameter`() {
            fun test(state: String? = null, asserter: URI.(Uri.() -> Unit) -> Unit) {
                val data = AuthorizationResponsePayload.SiopAuthentication("dummy", generateNonce(), state, "client_id")
                val response = AuthorizationResponse.QueryJwt(
                    redirectUriBase,
                    data,
                    JarmRequirement.Signed(JWSAlgorithm.RS256),
                )
                val redirectURI = response.encodeRedirectURI(Wallet.config)

                redirectURI.asserter {
                    val responseParameter = getQueryParameter("response")
                    assertNotNull(responseParameter)
                    val jwtClaimsSet = responseParameter.assertIsJwtSignedByWallet()
                    assertEquals(data.state, jwtClaimsSet.getClaim("state"))
                    assertEquals(data.idToken, jwtClaimsSet.getClaim("id_token"))
                }
            }

            genState().let { state -> test(state) { assertQueryURIContainsStateAnd(state, it) } }
            test { assertQueryURIDoesNotContainStateAnd(it) }
        }

        private fun URI.assertQueryURIContainsStateAnd(expectedState: String, assertions: Uri.() -> Unit) {
            assertQueryURI {
                assertions(this)
                assertEquals(expectedState, getQueryParameter("state"))
            }
        }

        private fun URI.assertQueryURIDoesNotContainStateAnd(assertions: Uri.() -> Unit) {
            assertQueryURI {
                assertions(this)
                assertNull(getQueryParameter("state"))
            }
        }

        private fun URI.assertQueryURI(assertions: Uri.() -> Unit) {
            assertions(toUri())
        }
    }

    @Nested
    @DisplayName("In fragment response")
    inner class FragmentResponse {

        private val redirectUriBase = URI("https://foo.bar")

        @Test
        fun `when no consensus, fragment must contain an error`() {
            fun test(state: String? = null, asserter: URI.((Map<String, String>) -> Unit) -> Unit) {
                val data = AuthorizationResponsePayload.NoConsensusResponseData(generateNonce(), state, "client_id")
                val response = AuthorizationResponse.Fragment(redirectUri = redirectUriBase, data = data)

                response.encodeRedirectURI()
                    .asserter { fragmentData ->
                        assertEquals(AuthorizationRequestErrorCode.USER_CANCELLED.code, fragmentData["error"])
                    }
            }

            genState().let { state -> test(state) { assertFragmentURIContainsStateAnd(state, it) } }
            test { assertFragmentURIDoesNotContainStateAnd(it) }
        }

        @Test
        fun `when invalid request, fragment must contain an error`() {
            fun test(state: String? = null, asserter: URI.((Map<String, String>) -> Unit) -> Unit) {
                val data =
                    AuthorizationResponsePayload.InvalidRequest(MissingNonce, generateNonce(), state, "client_id")
                val response = AuthorizationResponse.Fragment(redirectUri = redirectUriBase, data = data)

                response.encodeRedirectURI()
                    .asserter { fragmentData ->
                        val expectedErrorCode = AuthorizationRequestErrorCode.fromError(data.error)
                        assertEquals(expectedErrorCode.code, fragmentData["error"])
                    }
            }

            genState().let { state -> test(state) { assertFragmentURIContainsStateAnd(state, it) } }
            test { assertFragmentURIDoesNotContainStateAnd(it) }
        }

        @Test
        fun `when SIOPAuthentication, fragment must contain an id_token`() {
            fun test(state: String? = null, asserter: URI.((Map<String, String>) -> Unit) -> Unit) {
                val data = AuthorizationResponsePayload.SiopAuthentication("dummy", generateNonce(), state, "client_id")
                val response = AuthorizationResponse.Fragment(redirectUri = redirectUriBase, data = data)
                response.encodeRedirectURI()
                    .asserter { fragmentData ->
                        assertEquals(data.idToken, fragmentData["id_token"])
                    }
            }

            genState().let { state -> test(state) { assertFragmentURIContainsStateAnd(state, it) } }
            test { assertFragmentURIDoesNotContainStateAnd(it) }
        }

        @Test
        fun `when response mode is query_jwt, redirect_uri must contain a 'response' and a 'state' query parameter`() {
            fun test(state: String? = null, asserter: URI.((Map<String, String>) -> Unit) -> Unit) {
                val data = AuthorizationResponsePayload.SiopAuthentication("dummy", generateNonce(), state, "client_id")
                val response =
                    AuthorizationResponse.FragmentJwt(
                        redirectUri = redirectUriBase,
                        data = data,
                        jarmRequirement = JarmRequirement.Signed(JWSAlgorithm.RS256),
                    )
                response.encodeRedirectURI(Wallet.config)
                    .asserter { fragmentData ->
                        assertEquals(data.state, fragmentData["state"])
                        val responseParameter = fragmentData["response"]
                        assertNotNull(responseParameter)
                        val jwtClaimsSet = responseParameter.assertIsJwtSignedByWallet()
                        assertEquals(data.state, jwtClaimsSet.getClaim("state"))
                        assertEquals(data.idToken, jwtClaimsSet.getClaim("id_token"))
                    }
            }

            genState().let { state -> test(state) { assertFragmentURIContainsStateAnd(state, it) } }
            test { assertFragmentURIDoesNotContainStateAnd(it) }
        }

        private fun URI.assertFragmentURIContainsStateAnd(
            expectedState: String,
            assertions: (Map<String, String>) -> Unit,
        ) {
            assertFragmentURI {
                assertions(it)
                assertEquals(expectedState, it["state"])
            }
        }

        private fun URI.assertFragmentURIDoesNotContainStateAnd(
            assertions: (Map<String, String>) -> Unit,
        ) {
            assertFragmentURI {
                assertions(it)
                assertNull(it["state"])
            }
        }

        private fun URI.assertFragmentURI(
            assertions: (Map<String, String>) -> Unit,
        ) {
            val redirectUri = toUri().also { println(it) }
            assertNotNull(redirectUri.fragment)
            val map = redirectUri.fragment!!.parseUrlEncodedParameters().toMap().mapValues { it.value.first() }
            map.also(assertions)
        }
    }
}

private fun genState(): String = State().value
private fun JWTClaimsSet.vpTokenClaim(): JsonElement? =
    Json.parseToJsonElement(toString()).jsonObject["vp_token"]
