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
import com.nimbusds.jose.crypto.RSASSAVerifier
import com.nimbusds.jose.jwk.Curve
import com.nimbusds.jose.jwk.ECKey
import com.nimbusds.jose.jwk.JWKSet
import com.nimbusds.jose.jwk.KeyUse
import com.nimbusds.jose.jwk.gen.ECKeyGenerator
import com.nimbusds.jwt.SignedJWT
import com.nimbusds.oauth2.sdk.id.State
import eu.europa.ec.eudi.openid4vp.*
import eu.europa.ec.eudi.openid4vp.dcql.CredentialQuery
import eu.europa.ec.eudi.openid4vp.dcql.DCQL
import eu.europa.ec.eudi.openid4vp.dcql.QueryId
import eu.europa.ec.eudi.openid4vp.internal.request.*
import kotlinx.coroutines.test.runTest
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.jsonObject
import org.junit.jupiter.api.assertDoesNotThrow
import java.time.Clock
import kotlin.test.Test
import kotlin.test.assertIs
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

class AuthorizationResponseBuilderTest {

    internal object Wallet {

        val config = SiopOpenId4VPConfig(
            supportedClientIdPrefixes = listOf(SupportedClientIdPrefix.X509SanDns.NoValidation),
            jarmConfiguration = JarmConfiguration.Encryption(
                supportedAlgorithms = listOf(JWEAlgorithm.ECDH_ES),
                supportedMethods = listOf(EncryptionMethod.A256GCM),
            ),
            vpConfiguration = VPConfiguration(
                vpFormats = VpFormats(VpFormat.SdJwtVc.ES256, VpFormat.MsoMdoc.ES256),
            ),
            clock = Clock.systemDefaultZone(),
        )
    }

    internal object Verifier {

        private val jarmEncryptionKeyPair: ECKey = ECKeyGenerator(Curve.P_256)
            .keyUse(KeyUse.ENCRYPTION)
            .algorithm(JWEAlgorithm.ECDH_ES)
            .keyID("123")
            .generate()

        val metaDataRequestingNotEncryptedResponse = UnvalidatedClientMetaData(
            subjectSyntaxTypesSupported = listOf(
                "urn:ietf:params:oauth:jwk-thumbprint",
                "did:example",
                "did:key",
            ),
            vpFormats = VpFormatsTO.make(
                VpFormats(msoMdoc = VpFormat.MsoMdoc.ES256),
            ),
        )

        val metaDataRequestingEncryptedResponse = UnvalidatedClientMetaData(
            jwks = JWKSet(jarmEncryptionKeyPair).toJsonObject(true),
            authorizationEncryptedResponseAlg = jarmEncryptionKeyPair.algorithm.name,
            authorizationEncryptedResponseEnc = EncryptionMethod.A256GCM.name,
            vpFormats = VpFormatsTO.make(
                VpFormats(msoMdoc = VpFormat.MsoMdoc.ES256),
            ),
        )

        private fun JWKSet.toJsonObject(publicKeysOnly: Boolean = true): JsonObject =
            Json.parseToJsonElement(this.toString(publicKeysOnly)).jsonObject
    }

    private fun genState(): String {
        return State().value
    }

    @Test
    fun `id token request should produce a response with id token JWT`(): Unit = runTest {
        fun test(state: String? = null) {
            val verifierMetaData = ClientMetaDataValidator.validateClientMetaData(
                Verifier.metaDataRequestingNotEncryptedResponse,
                ResponseMode.DirectPost("https://respond.here".asURL().getOrThrow()),
            )

            val siopAuthRequestObject =
                ResolvedRequestObject.SiopAuthentication(
                    idTokenType = listOf(IdTokenType.AttesterSigned),
                    subjectSyntaxTypesSupported = verifierMetaData.subjectSyntaxTypesSupported,
                    jarmRequirement = Wallet.config.jarmRequirement(verifierMetaData),
                    client = Client.Preregistered("https%3A%2F%2Fclient.example.org%2Fcb", "Verifier"),
                    nonce = "0S6_WzA2Mj",
                    responseMode = ResponseMode.DirectPost("https://respond.here".asURL().getOrThrow()),
                    state = state,
                    scope = Scope.make("openid") ?: throw IllegalStateException(),
                )

            val rsaJWK = SiopIdTokenBuilder.randomKey()

            val idTokenConsensus = Consensus.PositiveConsensus.IdTokenConsensus(
                idToken = SiopIdTokenBuilder.build(
                    request = siopAuthRequestObject,
                    holderInfo = HolderInfo("foo@bar.com", "foo bar"),
                    rsaJWK = rsaJWK,
                ),
            )

            val response = siopAuthRequestObject.responseWith(idTokenConsensus, null)
            assertIs<AuthorizationResponse.DirectPost>(response)
            val data = response.data
            assertIs<AuthorizationResponsePayload.SiopAuthentication>(data)
            val idToken = data.idToken
            assertTrue("Id Token signature could not be verified") {
                SignedJWT.parse(idToken).verify(RSASSAVerifier(rsaJWK))
            }
        }

        test(genState())
        test()
    }

    @Test
    fun `when direct_post jwt, builder should return DirectPostJwt with JarmSpec of correct type`() = runTest {
        fun test(state: String? = null) {
            val responseMode = ResponseMode.DirectPostJwt("https://respond.here".asURL().getOrThrow())
            val verifierMetaData = assertDoesNotThrow {
                ClientMetaDataValidator.validateClientMetaData(Verifier.metaDataRequestingEncryptedResponse, responseMode)
            }

            val resolvedRequest =
                ResolvedRequestObject.OpenId4VPAuthorization(
                    query =
                        DCQL(
                            credentials = listOf(
                                CredentialQuery(
                                    id = QueryId("pdId"),
                                    format = Format("foo"),
                                ),
                            ),
                        ),
                    jarmRequirement = Wallet.config.jarmRequirement(verifierMetaData),
                    vpFormats = VpFormats(msoMdoc = VpFormat.MsoMdoc.ES256),
                    client = Client.Preregistered("https%3A%2F%2Fclient.example.org%2Fcb", "Verifier"),
                    nonce = "0S6_WzA2Mj",
                    responseMode = responseMode,
                    state = state,
                    transactionData = null,
                    verifierAttestations = null,
                )

            val vpTokenConsensus = Consensus.PositiveConsensus.VPTokenConsensus(
                VerifiablePresentations(
                    mapOf(
                        QueryId("pdId") to listOf(VerifiablePresentation.Generic("dummy_vp_token")),
                    ),
                ),
            )
            val response = resolvedRequest.responseWith(vpTokenConsensus, null)

            assertTrue("Response not of the expected type DirectPostJwt") { response is AuthorizationResponse.DirectPostJwt }
            assertIs<AuthorizationResponse.DirectPostJwt>(response)
            val jarmOption = response.jarmRequirement
            assertNotNull(jarmOption)
            assertIs<JarmRequirement.Encrypted>(jarmOption)
        }

        test(genState())
        test()
    }
}
