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

import com.nimbusds.jose.EncryptionMethod
import com.nimbusds.jose.JWEAlgorithm
import com.nimbusds.jose.crypto.ECDHDecrypter
import com.nimbusds.jose.jwk.Curve
import com.nimbusds.jose.jwk.ECKey
import com.nimbusds.jose.jwk.JWKSet
import com.nimbusds.jose.jwk.KeyUse
import com.nimbusds.jose.jwk.gen.ECKeyGenerator
import com.nimbusds.jose.util.Base64URL
import com.nimbusds.jwt.EncryptedJWT
import com.nimbusds.jwt.JWTClaimsSet
import com.nimbusds.oauth2.sdk.id.State
import eu.europa.ec.eudi.openid4vp.*
import eu.europa.ec.eudi.openid4vp.RequestValidationError.MissingNonce
import eu.europa.ec.eudi.openid4vp.dcql.*
import eu.europa.ec.eudi.openid4vp.dcql.ClaimPathElement.Claim
import eu.europa.ec.eudi.openid4vp.internal.request.ClientMetaDataValidator
import eu.europa.ec.eudi.openid4vp.internal.request.UnvalidatedClientMetaData
import eu.europa.ec.eudi.openid4vp.internal.request.VpFormatsTO
import eu.europa.ec.eudi.openid4vp.internal.request.asURL
import eu.europa.ec.eudi.openid4vp.internal.response.DefaultDispatcherTest.Verifier.assertIsJwtEncryptedWithVerifiersPublicKey
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
import kotlin.test.*

class DefaultDispatcherTest {

    //
    // Verifier settings
    //

    internal object Verifier {

        val CLIENT = Client.Preregistered("https://client.example.org", "Verifier")

        val responseEncryptionKeyPair: ECKey = ECKeyGenerator(Curve.P_256)
            .keyUse(KeyUse.ENCRYPTION)
            .algorithm(JWEAlgorithm.ECDH_ES)
            .keyID("123")
            .generate()

        val metaDataRequestingEncryptedResponse = UnvalidatedClientMetaData(
            jwks = JWKSet(responseEncryptionKeyPair).toJsonObject(true),
            responseEncryptionMethodsSupported = listOf(EncryptionMethod.A256GCM.name),
            vpFormats = VpFormatsTO.make(
                VpFormats(msoMdoc = VpFormat.MsoMdoc.ES256),
            ),
        )

        private fun JWKSet.toJsonObject(publicKeysOnly: Boolean = true): JsonObject =
            Json.parseToJsonElement(this.toString(publicKeysOnly)).jsonObject

        fun String.assertIsJwtEncryptedWithVerifiersPublicKey(): EncryptedJWT {
            val jwt = assertDoesNotThrow { EncryptedJWT.parse(this) }
            val rsaDecrypter = ECDHDecrypter(responseEncryptionKeyPair)
            jwt.decrypt(rsaDecrypter)
            return jwt
        }

        fun createOpenId4VPRequest(
            unvalidatedClientMetaData: UnvalidatedClientMetaData,
            responseMode: ResponseMode,
            state: String? = null,
        ): ResolvedRequestObject.OpenId4VPAuthorization {
            val clientMetadataValidated =
                ClientMetaDataValidator.validateClientMetaData(
                    unvalidatedClientMetaData,
                    responseMode,
                    Wallet.config.responseEncryptionConfiguration,
                )

            return ResolvedRequestObject.OpenId4VPAuthorization(
                query =
                    DCQL(
                        credentials = listOf(
                            CredentialQuery(
                                id = QueryId("pdId"),
                                format = Format("foo"),
                            ),
                        ),
                    ),
                responseEncryptionRequirement = clientMetadataValidated.responseEncryptionRequirement,
                vpFormats = VpFormats(msoMdoc = VpFormat.MsoMdoc.ES256),
                client = CLIENT,
                nonce = "0S6_WzA2Mj",
                responseMode = responseMode,
                state = state ?: genState(),
                transactionData = null,
                verifierAttestations = null,
            )
        }
    }

    //
    // Wallet settings
    //

    private object Wallet {
        val config = SiopOpenId4VPConfig(
            supportedClientIdPrefixes = listOf(SupportedClientIdPrefix.X509SanDns.NoValidation),
            responseEncryptionConfiguration = ResponseEncryptionConfiguration.Supported(
                supportedAlgorithms = listOf(Verifier.responseEncryptionKeyPair.algorithm as JWEAlgorithm),
                supportedMethods = listOf(EncryptionMethod.A256GCM),
            ),
            vpConfiguration = VPConfiguration(
                vpFormats = VpFormats(VpFormat.SdJwtVc.ES256, VpFormat.MsoMdoc.ES256),
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

            val httpClient = createHttpClient(mockEngine).config {
                expectSuccess = true
                install(ContentNegotiation) {
                    json()
                }
            }

            return DefaultDispatcher { httpClient }
        }
    }

    @Nested
    @DisplayName("Encrypted response")
    inner class DirectPostJwtResponse {

        @Test
        fun `client metadata does not match with wallet's supported algorithms`(): Unit = runTest {
            val responseMode = ResponseMode.QueryJwt(URI.create("foo://bar"))

            val exception = assertThrows<AuthorizationRequestException> {
                ClientMetaDataValidator.validateClientMetaData(
                    Verifier.metaDataRequestingEncryptedResponse,
                    responseMode,
                    ResponseEncryptionConfiguration.NotSupported,
                )
            }

            assertIs<RequestValidationError.UnsupportedClientMetaData>(exception.error)
        }

        @Test
        fun `if response type direct_post jwt, JWE should be returned if only encryption info specified`() = runTest {
            val verifierRequest = Verifier.createOpenId4VPRequest(
                Verifier.metaDataRequestingEncryptedResponse,
                ResponseMode.DirectPostJwt("https://respond.here".asURL().getOrThrow()),
            )

            suspend fun test(
                verifiablePresentations: List<VerifiablePresentation>,
                redirectUri: URI? = null,
            ) {
                val vpTokenConsensus = Consensus.PositiveConsensus.VPTokenConsensus(
                    VerifiablePresentations(
                        mapOf(
                            QueryId("psId") to verifiablePresentations,
                        ),
                    ),
                )

                val dispatcher = Wallet.createDispatcherWithVerifierAsserting(redirectUri) { responseParam ->
                    val encryptedJwt = responseParam.assertIsJwtEncryptedWithVerifiersPublicKey()
                    assertEquals(Base64URL.encode(verifierRequest.nonce), encryptedJwt.header.agreementPartyVInfo)
                    assertEquals(Base64URL.encode("dummy_apu"), encryptedJwt.header.agreementPartyUInfo)

                    val jwtClaimSet = encryptedJwt.jwtClaimsSet
                    val vpTokenClaim = jwtClaimSet.vpTokenClaim()
                    assertEquals(vpTokenConsensus.verifiablePresentations.asJsonObject(), vpTokenClaim)
                }

                val outcome = dispatcher.dispatch(
                    verifierRequest,
                    vpTokenConsensus,
                    EncryptionParameters.DiffieHellman(Base64URL.encode("dummy_apu")),
                )
                val expectedOutcome = DispatchOutcome.VerifierResponse.Accepted(redirectUri)
                assertEquals(expectedOutcome, outcome)
            }

            test(
                listOf(VerifiablePresentation.Generic("dummy_vp_token")),
                redirectUri = null,
            )
            test(
                listOf(VerifiablePresentation.Generic("dummy_vp_token")),
                redirectUri = URI.create("https://redirect.here"),
            )
        }

        @Test
        fun `if response direct_post jwt with encryption required, negative consensus must be dispatched in response`() = runTest {
            val verifierRequest = Verifier.createOpenId4VPRequest(
                Verifier.metaDataRequestingEncryptedResponse,
                ResponseMode.DirectPostJwt("https://respond.here".asURL().getOrThrow()),
            )

            val negativeConsensus = Consensus.NegativeConsensus

            val dispatcher = Wallet.createDispatcherWithVerifierAsserting { responseParam ->
                val encryptedJwt = responseParam.assertIsJwtEncryptedWithVerifiersPublicKey()
                assertEquals(Base64URL.encode(verifierRequest.nonce), encryptedJwt.header.agreementPartyVInfo)
                assertEquals(Base64URL.encode("dummy_apu"), encryptedJwt.header.agreementPartyUInfo)

                val jwtClaimSet = encryptedJwt.jwtClaimsSet
                val errorClam = jwtClaimSet.getStringClaim("error")
                assertNotNull(errorClam)
                assertEquals("access_denied", errorClam)
            }

            dispatcher.dispatch(
                verifierRequest,
                negativeConsensus,
                EncryptionParameters.DiffieHellman(Base64URL.encode("dummy_apu")),
            )
        }

        @Test
        fun `support vp_token with multiple verifiable presentations`() = runTest {
            suspend fun test(verifiablePresentations: VerifiablePresentations, redirectUri: URI? = null) {
                val responseMode = ResponseMode.DirectPostJwt("https://respond.here".asURL().getOrThrow())
                val resolvedRequest = Verifier.createOpenId4VPRequest(Verifier.metaDataRequestingEncryptedResponse, responseMode)
                val vpTokenConsensus = Consensus.PositiveConsensus.VPTokenConsensus(
                    verifiablePresentations = verifiablePresentations,
                )

                val dispatcher = Wallet.createDispatcherWithVerifierAsserting(redirectUri) { responseParam ->
                    val jwtClaimsSet = responseParam.assertIsJwtEncryptedWithVerifiersPublicKey().jwtClaimsSet
                    assertEquals(
                        vpTokenConsensus.verifiablePresentations.asJsonObject(),
                        jwtClaimsSet.vpTokenClaim(),
                    )
                }

                val expectedOutcome = DispatchOutcome.VerifierResponse.Accepted(redirectUri)
                val outcome = dispatcher.dispatch(
                    resolvedRequest,
                    vpTokenConsensus,
                    EncryptionParameters.DiffieHellman(Base64URL.encode("dummy_apu")),
                )
                assertEquals(expectedOutcome, outcome)
            }

            test(vpTokenWithMultipleGenericPresentations())
            test(vpTokenWithMultipleGenericPresentations(), URI.create("https://redirect.here"))
            test(vpTokenWithMultipleMixedPresentations(), URI.create("https://redirect.here"))
        }

        @Test
        fun `support dcql vp_token`() = runTest {
            suspend fun test(resolvedRequest: ResolvedRequestObject, consensus: Consensus, redirectUri: URI? = null) {
                val dispatcher = Wallet.createDispatcherWithVerifierAsserting(redirectUri) { responseParam ->
                    val jwtClaimsSet = responseParam.assertIsJwtEncryptedWithVerifiersPublicKey().jwtClaimsSet
                    when (consensus) {
                        is Consensus.PositiveConsensus.VPTokenConsensus -> {
                            assertEquals(
                                consensus.verifiablePresentations.asJsonObject(),
                                jwtClaimsSet.vpTokenClaim(),
                            )
                        }

                        is Consensus.PositiveConsensus.IdAndVPTokenConsensus -> {
                            assertNotNull(jwtClaimsSet.claims["id_token"], "Expected id_token")
                            assertEquals(
                                consensus.verifiablePresentations.asJsonObject(),
                                jwtClaimsSet.vpTokenClaim(),
                            )
                        }

                        else -> fail("Expected positive consensus")
                    }
                }

                val expectedOutcome = DispatchOutcome.VerifierResponse.Accepted(redirectUri)
                val outcome = dispatcher.dispatch(
                    resolvedRequest,
                    consensus,
                    EncryptionParameters.DiffieHellman(Base64URL.encode("dummy_apu")),
                )
                assertEquals(expectedOutcome, outcome)
            }

            val responseMode = ResponseMode.DirectPostJwt("https://respond.here".asURL().getOrThrow())
            test(
                createOpenID4VPRequestWithDCQL(Verifier.metaDataRequestingEncryptedResponse, responseMode),
                Consensus.PositiveConsensus.VPTokenConsensus(dcqlVpTokenWithGenericPresentation()),
            )
            test(
                createOpenID4VPRequestWithDCQL(Verifier.metaDataRequestingEncryptedResponse, responseMode),
                Consensus.PositiveConsensus.VPTokenConsensus(dcqlVpTokenWithGenericPresentation()),
            )
            test(
                createSiopOpenID4VPRequestWithDCQL(Verifier.metaDataRequestingEncryptedResponse, responseMode),
                Consensus.PositiveConsensus.IdAndVPTokenConsensus("dummy_jwt", dcqlVpTokenWithGenericPresentation()),
            )
            test(
                createSiopOpenID4VPRequestWithDCQL(Verifier.metaDataRequestingEncryptedResponse, responseMode),
                Consensus.PositiveConsensus.IdAndVPTokenConsensus("dummy_jwt", dcqlVpTokenWithJsonPresentation()),
            )
        }

        private fun vpTokenWithMultipleMixedPresentations(): VerifiablePresentations =
            VerifiablePresentations(
                mapOf(
                    QueryId("psId") to listOf(
                        VerifiablePresentation.Generic("dummy_vp_token"),
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
                ),
            )

        private fun vpTokenWithMultipleGenericPresentations(): VerifiablePresentations =
            VerifiablePresentations(
                mapOf(
                    QueryId("psId") to listOf(
                        VerifiablePresentation.Generic("dummy_vp_token_1"),
                        VerifiablePresentation.Generic("dummy_vp_token_2"),
                        VerifiablePresentation.Generic("dummy_vp_token_3"),
                    ),
                ),
            )

        private fun createOpenID4VPRequestWithDCQL(
            unvalidatedClientMetaData: UnvalidatedClientMetaData,
            responseMode: ResponseMode.DirectPostJwt,
        ): ResolvedRequestObject.OpenId4VPAuthorization {
            val clientMetadataValidated =
                ClientMetaDataValidator.validateClientMetaData(
                    unvalidatedClientMetaData,
                    responseMode,
                    Wallet.config.responseEncryptionConfiguration,
                )

            return ResolvedRequestObject.OpenId4VPAuthorization(
                query =
                    DCQL(
                        credentials = listOf(
                            testCredentialQuery(),
                        ),
                    ),
                responseEncryptionRequirement = clientMetadataValidated.responseEncryptionRequirement,
                vpFormats = VpFormats(msoMdoc = VpFormat.MsoMdoc.ES256),
                client = Verifier.CLIENT,
                nonce = "0S6_WzA2Mj",
                responseMode = responseMode,
                state = genState(),
                transactionData = null,
                verifierAttestations = null,
            )
        }

        private fun createSiopOpenID4VPRequestWithDCQL(
            unvalidatedClientMetaData: UnvalidatedClientMetaData,
            responseMode: ResponseMode.DirectPostJwt,
        ): ResolvedRequestObject.SiopOpenId4VPAuthentication {
            val clientMetadataValidated =
                ClientMetaDataValidator.validateClientMetaData(
                    unvalidatedClientMetaData,
                    responseMode,
                    Wallet.config.responseEncryptionConfiguration,
                )

            return ResolvedRequestObject.SiopOpenId4VPAuthentication(
                client = Verifier.CLIENT,
                responseMode = responseMode,
                state = genState(),
                nonce = "0S6_WzA2Mj",
                responseEncryptionRequirement = clientMetadataValidated.responseEncryptionRequirement,
                vpFormats = VpFormats(msoMdoc = VpFormat.MsoMdoc.ES256),
                idTokenType = listOf(IdTokenType.SubjectSigned),
                subjectSyntaxTypesSupported = listOf(SubjectSyntaxType.DecentralizedIdentifier("")),
                scope = Scope.OpenId,
                query =
                    DCQL(
                        credentials = listOf(
                            testCredentialQuery(),
                        ),
                    ),
                transactionData = null,
                verifierAttestations = null,
            )
        }

        private fun dcqlVpTokenWithGenericPresentation(): VerifiablePresentations =
            VerifiablePresentations(
                mapOf(
                    QueryId("my_credential") to listOf(VerifiablePresentation.Generic("dummy_vp_token")),
                ),
            )

        private fun dcqlVpTokenWithJsonPresentation(): VerifiablePresentations =
            VerifiablePresentations(
                mapOf(
                    QueryId("my_credential") to listOf(
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
                ),
            )

        private fun testCredentialQuery(): CredentialQuery = CredentialQuery(
            QueryId("my_credential"),
            Format.SdJwtVc,
            meta = JsonObject(
                mapOf(
                    "vct_values" to
                        JsonArray(
                            listOf(
                                JsonPrimitive("https://credentials.example.com/identity_credential"),
                            ),
                        ),
                ),
            ),
            claims = listOf(
                ClaimsQuery(
                    path = ClaimPath(listOf(Claim("last_name"))),
                ),
                ClaimsQuery(
                    path = ClaimPath(listOf(Claim("first_name"))),
                ),
                ClaimsQuery(
                    path = ClaimPath(listOf(Claim("address"), Claim("street_address"))),
                ),
            ),
        )
    }

    @Nested
    @DisplayName("In query response")
    inner class QueryResponse {

        private val redirectUriBase = URI("https://foo.bar")

        @Test
        fun `when no consensus, redirect_uri must contain an error query parameter`() {
            fun test(state: String? = null, asserter: URI.(URI.() -> Unit) -> Unit) {
                val data = AuthorizationResponsePayload.NoConsensusResponseData(
                    generateNonce(),
                    state,
                    VerifierId(ClientIdPrefix.PreRegistered, "client_id"),
                )
                val response = AuthorizationResponse.Query(redirectUri = redirectUriBase, data = data)
                response.encodeRedirectURI()
                    .asserter {
                        assertEquals(AuthorizationRequestErrorCode.ACCESS_DENIED.code, getQueryParameter("error"))
                    }
            }

            genState().let { state -> test(state) { assertQueryURIContainsStateAnd(state, it) } }
            test { assertQueryURIDoesNotContainStateAnd(it) }
        }

        @Test
        fun `when invalid request, redirect_uri must contain an error query parameter`() {
            fun test(state: String? = null, asserter: URI.(URI.() -> Unit) -> Unit) {
                val data =
                    AuthorizationResponsePayload.InvalidRequest(
                        MissingNonce,
                        generateNonce(),
                        state,
                        VerifierId(ClientIdPrefix.PreRegistered, "client_id"),
                    )
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
            fun test(state: String? = null, asserter: URI.(URI.() -> Unit) -> Unit) {
                val data = AuthorizationResponsePayload.SiopAuthentication(
                    "dummy",
                    generateNonce(),
                    state,
                    VerifierId(ClientIdPrefix.PreRegistered, "client_id"),
                    EncryptionParameters.DiffieHellman(Base64URL.encode("dummy_apu")),
                )
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
        fun `when response mode is query_jwt, redirect_uri must contain a 'response' query parameter`() {
            fun test(state: String? = null, asserter: URI.(URI.() -> Unit) -> Unit) {
                val data = AuthorizationResponsePayload.SiopAuthentication(
                    "dummy",
                    generateNonce(),
                    state,
                    VerifierId(ClientIdPrefix.PreRegistered, "client_id"),
                    EncryptionParameters.DiffieHellman(Base64URL.encode("dummy_apu")),
                )
                val response = AuthorizationResponse.QueryJwt(
                    redirectUriBase,
                    data,
                    ResponseEncryptionRequirement(
                        encryptionAlgorithm = Verifier.responseEncryptionKeyPair.algorithm as JWEAlgorithm,
                        encryptionMethod = EncryptionMethod.parse(
                            Verifier.metaDataRequestingEncryptedResponse.responseEncryptionMethodsSupported.orEmpty().first(),
                        ),
                        clientKey = Verifier.responseEncryptionKeyPair.toPublicJWK(),
                    ),
                )
                val redirectURI = response.encodeRedirectURI()

                redirectURI.asserter {
                    val responseParameter = getQueryParameter("response")
                    assertNotNull(responseParameter)
                    val jwtClaimsSet = responseParameter.assertIsJwtEncryptedWithVerifiersPublicKey().jwtClaimsSet
                    assertEquals(data.state, jwtClaimsSet.getClaim("state"))
                    assertEquals(data.idToken, jwtClaimsSet.getClaim("id_token"))
                }
            }

            test(genState()) { assertQueryURIDoesNotContainStateAnd(it) }
            test { assertQueryURIDoesNotContainStateAnd(it) }
        }

        @Test
        fun `when query_jwt with encryption and negative consensus, redirect_uri must contain error ACCESS_DENIED in response`() = runTest {
            suspend fun test(state: String? = null, asserter: URI.(URI.() -> Unit) -> Unit) {
                val verifierRequest = Verifier.createOpenId4VPRequest(
                    Verifier.metaDataRequestingEncryptedResponse,
                    ResponseMode.QueryJwt("https://respond.here".asURL().getOrThrow().toURI()),
                    state,
                )

                val dispatcher = DefaultDispatcher { HttpClient() }

                val outcome =
                    dispatcher.dispatch(
                        verifierRequest,
                        Consensus.NegativeConsensus,
                        EncryptionParameters.DiffieHellman(Base64URL.encode("dummy_apu")),
                    )

                assertIs<DispatchOutcome.RedirectURI>(outcome)

                outcome.value.asserter {
                    val responseParameter = getQueryParameter("response")
                    assertNotNull(responseParameter)
                    val encryptedJwt = responseParameter.assertIsJwtEncryptedWithVerifiersPublicKey()
                    assertEquals(Base64URL.encode(verifierRequest.nonce), encryptedJwt.header.agreementPartyVInfo)
                    assertEquals(Base64URL.encode("dummy_apu"), encryptedJwt.header.agreementPartyUInfo)

                    val errorClam = encryptedJwt.jwtClaimsSet.getStringClaim("error")
                    val state = encryptedJwt.jwtClaimsSet.getStringClaim("state")

                    assertNotNull(errorClam)
                    assertEquals("access_denied", errorClam)
                    assertEquals(state, errorClam)
                }
            }

            test(genState()) {}
            test {}
        }

        private fun URI.assertQueryURIContainsStateAnd(expectedState: String, assertions: URI.() -> Unit) {
            assertQueryURI {
                assertions(this)
                assertEquals(expectedState, getQueryParameter("state"))
            }
        }

        private fun URI.assertQueryURIDoesNotContainStateAnd(assertions: URI.() -> Unit) {
            assertQueryURI {
                assertions(this)
                assertNull(getQueryParameter("state"))
            }
        }

        private fun URI.assertQueryURI(assertions: URI.() -> Unit) {
            assertions(this)
        }
    }

    @Nested
    @DisplayName("In fragment response")
    inner class FragmentResponse {

        private val redirectUriBase = URI("https://foo.bar")

        @Test
        fun `when no consensus, fragment must contain an error`() {
            fun test(state: String? = null, asserter: URI.((Map<String, String>) -> Unit) -> Unit) {
                val data = AuthorizationResponsePayload.NoConsensusResponseData(
                    generateNonce(),
                    state,
                    VerifierId(ClientIdPrefix.PreRegistered, "client_id"),
                )
                val response = AuthorizationResponse.Fragment(redirectUri = redirectUriBase, data = data)

                response.encodeRedirectURI()
                    .asserter { fragmentData ->
                        assertEquals(AuthorizationRequestErrorCode.ACCESS_DENIED.code, fragmentData["error"])
                    }
            }

            genState().let { state -> test(state) { assertFragmentURIContainsStateAnd(state, it) } }
            test { assertFragmentURIDoesNotContainStateAnd(it) }
        }

        @Test
        fun `when invalid request, fragment must contain an error`() {
            fun test(state: String? = null, asserter: URI.((Map<String, String>) -> Unit) -> Unit) {
                val data =
                    AuthorizationResponsePayload.InvalidRequest(
                        MissingNonce,
                        generateNonce(),
                        state,
                        VerifierId(ClientIdPrefix.PreRegistered, "client_id"),
                    )
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
                val data = AuthorizationResponsePayload.SiopAuthentication(
                    "dummy",
                    generateNonce(),
                    state,
                    VerifierId(ClientIdPrefix.PreRegistered, "client_id"),
                    EncryptionParameters.DiffieHellman(Base64URL.encode("dummy_apu")),
                )
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
        fun `when SiopOpenId4VPAuthentication, fragment must contain an id_token`() {
            fun test(state: String? = null, asserter: URI.((Map<String, String>) -> Unit) -> Unit) {
                val data = AuthorizationResponsePayload.SiopOpenId4VPAuthentication(
                    "dummy",
                    VerifiablePresentations(
                        mapOf(
                            QueryId("my_credential") to listOf(VerifiablePresentation.Generic("dummy_vp_token")),
                        ),
                    ),
                    generateNonce(),
                    state,
                    VerifierId(ClientIdPrefix.PreRegistered, "client_id"),
                    EncryptionParameters.DiffieHellman(Base64URL.encode("dummy_apu")),
                )
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
        fun `when response mode is fragment_jwt, redirect_uri must contain a 'response' query parameter`() {
            fun test(state: String? = null, asserter: URI.((Map<String, String>) -> Unit) -> Unit) {
                val data = AuthorizationResponsePayload.SiopAuthentication(
                    "dummy",
                    generateNonce(),
                    state,
                    VerifierId(ClientIdPrefix.PreRegistered, "client_id"),
                    EncryptionParameters.DiffieHellman(Base64URL.encode("dummy_apu")),
                )
                val response =
                    AuthorizationResponse.FragmentJwt(
                        redirectUri = redirectUriBase,
                        data = data,
                        responseEncryptionRequirement = ResponseEncryptionRequirement(
                            encryptionAlgorithm = Verifier.responseEncryptionKeyPair.algorithm as JWEAlgorithm,
                            encryptionMethod = EncryptionMethod.parse(
                                Verifier.metaDataRequestingEncryptedResponse.responseEncryptionMethodsSupported.orEmpty().first(),
                            ),
                            clientKey = Verifier.responseEncryptionKeyPair.toPublicJWK(),
                        ),
                    )
                response.encodeRedirectURI()
                    .asserter { fragmentData ->
                        val responseParameter = fragmentData["response"]
                        assertNotNull(responseParameter)
                        val jwtClaimsSet = responseParameter.assertIsJwtEncryptedWithVerifiersPublicKey().jwtClaimsSet
                        assertEquals(data.state, jwtClaimsSet.getClaim("state"))
                        assertEquals(data.idToken, jwtClaimsSet.getClaim("id_token"))
                    }
            }

            test(genState()) { assertFragmentURIDoesNotContainStateAnd(it) }
            test { assertFragmentURIDoesNotContainStateAnd(it) }
        }

        @Test
        fun `when fragment_jwt with encryption and negative consensus, redirect_uri must contain ACCESS_DENIED in response`() = runTest {
            suspend fun test(state: String? = null, asserter: URI.(URI.() -> Unit) -> Unit) {
                val verifierRequest = Verifier.createOpenId4VPRequest(
                    Verifier.metaDataRequestingEncryptedResponse,
                    ResponseMode.FragmentJwt("https://respond.here".asURL().getOrThrow().toURI()),
                    state,
                )

                val dispatcher = DefaultDispatcher { HttpClient() }

                val outcome =
                    dispatcher.dispatch(
                        verifierRequest,
                        Consensus.NegativeConsensus,
                        EncryptionParameters.DiffieHellman(Base64URL.encode("dummy_apu")),
                    )

                assertIs<DispatchOutcome.RedirectURI>(outcome)

                outcome.value.asserter {
                    val responseParameter = getQueryParameter("response")
                    assertNotNull(responseParameter)
                    val encryptedJwt = responseParameter.assertIsJwtEncryptedWithVerifiersPublicKey()
                    assertEquals(Base64URL.encode(verifierRequest.nonce), encryptedJwt.header.agreementPartyVInfo)
                    assertEquals(Base64URL.encode("dummy_apu"), encryptedJwt.header.agreementPartyUInfo)

                    val errorClam = encryptedJwt.jwtClaimsSet.getStringClaim("error")
                    val state = encryptedJwt.jwtClaimsSet.getStringClaim("state")

                    assertNotNull(errorClam)
                    assertEquals("access_denied", errorClam)
                    assertEquals(state, errorClam)
                }
            }

            test(genState()) {}
            test {}
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
            assertNotNull(rawFragment)
            val map = rawFragment.parseUrlEncodedParameters().toMap().mapValues { it.value.first() }
            map.also(assertions)
        }
    }
}

private fun genState(): String = State().value
private fun JWTClaimsSet.vpTokenClaim(): JsonElement? =
    Json.parseToJsonElement(toString()).jsonObject["vp_token"]

private fun URI.getQueryParameter(name: String): String? =
    rawQuery.parseUrlEncodedParameters().toMap().mapValues { it.value.first() }[name]
