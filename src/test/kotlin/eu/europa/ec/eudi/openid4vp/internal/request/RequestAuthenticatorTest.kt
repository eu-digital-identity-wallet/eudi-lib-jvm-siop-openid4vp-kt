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
package eu.europa.ec.eudi.openid4vp.internal.request

import com.nimbusds.jose.*
import com.nimbusds.jose.crypto.factories.DefaultJWSSignerFactory
import com.nimbusds.jose.jwk.Curve
import com.nimbusds.jose.jwk.ECKey
import com.nimbusds.jose.jwk.JWK
import com.nimbusds.jose.jwk.KeyUse
import com.nimbusds.jose.jwk.gen.ECKeyGenerator
import com.nimbusds.jose.util.Base64URL
import com.nimbusds.jwt.JWTClaimsSet
import com.nimbusds.jwt.SignedJWT
import eu.europa.ec.eudi.openid4vp.*
import eu.europa.ec.eudi.openid4vp.internal.AbsoluteDIDUrl
import eu.europa.ec.eudi.openid4vp.internal.DID
import kotlinx.coroutines.test.runTest
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import org.junit.jupiter.api.DisplayName
import org.junit.jupiter.api.Nested
import org.junit.jupiter.api.assertThrows
import java.net.URI
import java.time.Clock
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertTrue

class ClientAuthenticatorTest {

    @DisplayName("when handling a request")
    @Nested
    inner class ClientAuthenticatorCommonTest {

        private val cfg = SiopOpenId4VPConfig(
            supportedClientIdSchemes = listOf(
                SupportedClientIdScheme.RedirectUri,
            ),
            vpConfiguration = VPConfiguration(
                vpFormats = VpFormats(VpFormat.MsoMdoc, VpFormat.SdJwtVc.ES256),
            ),
            clock = Clock.systemDefaultZone(),
        )
        private val clientAuthenticator = ClientAuthenticator(cfg)

        @Test
        fun `if client_id is missing, authentication fails`() = runTest {
            val request = UnvalidatedRequestObject(clientId = null).plain()
            assertFailsWithError<RequestValidationError.MissingClientId> {
                clientAuthenticator.authenticateClient(request)
            }
        }

        @Test
        fun `if client_id scheme is invalid, authentication fails`() = runTest {
            val request = UnvalidatedRequestObject(
                clientId = "bar:foo",
                responseMode = "bar",
            ).plain()

            assertFailsWithError<RequestValidationError.InvalidClientIdScheme> {
                clientAuthenticator.authenticateClient(request)
            }
        }
    }

    @DisplayName("when handling a request with `redirect_uri` scheme")
    @Nested
    inner class ClientAuthenticatorWhenUsingRedirectUriTest {
        private val clientId = URI.create("http://localhost:8080")
        private val cfg = SiopOpenId4VPConfig(
            supportedClientIdSchemes = listOf(
                SupportedClientIdScheme.RedirectUri,
            ),
            vpConfiguration = VPConfiguration(
                vpFormats = VpFormats(VpFormat.MsoMdoc, VpFormat.SdJwtVc.ES256),
            ),
        )
        private val clientAuthenticator = ClientAuthenticator(cfg)

        @Test
        fun `if request is not signed, authentication succeeds`() =
            runTest {
                val request = UnvalidatedRequestObject(
                    clientId = "redirect_uri:$clientId",
                ).plain()

                val client = clientAuthenticator.authenticateClient(request)
                assertEquals(AuthenticatedClient.RedirectUri(clientId), client)
            }

        @Test
        fun `if  request is signed, authentication fails`() = runTest {
            val (alg, key) = randomKey()
            val request = UnvalidatedRequestObject(
                clientId = "redirect_uri:$clientId",
            ).signed(alg, key)

            val error = assertFailsWithError<RequestValidationError.InvalidClientIdScheme> {
                clientAuthenticator.authenticateClient(request)
            }
            assertEquals("RedirectUri cannot be used in signed request", error.value)
        }
    }

    @DisplayName("when handling a request with `did` scheme")
    @Nested
    inner class ClientAuthenticatorWhenUsingDIDTest {
        private val clientId = DID.parse("did:example:123").getOrThrow()
        private val keyUrl = AbsoluteDIDUrl.parse("$clientId#01").getOrThrow()
        private val algAndKey = randomKey()
        private val cfg = SiopOpenId4VPConfig(
            supportedClientIdSchemes = listOf(
                SupportedClientIdScheme.DID { url ->
                    assertEquals(keyUrl.uri, url)
                    algAndKey.second.toPublicKey()
                },
            ),
            vpConfiguration = VPConfiguration(
                vpFormats = VpFormats(VpFormat.MsoMdoc, VpFormat.SdJwtVc.ES256),
            ),
        )
        private val clientAuthenticator = ClientAuthenticator(cfg)
        private val requestObject = UnvalidatedRequestObject(
            clientId = clientId.toString(),
        )

        @Test
        fun `if request is not signed, authentication fails`() = runTest {
            val request = requestObject.plain()

            val error = assertFailsWithError<RequestValidationError.InvalidClientIdScheme> {
                clientAuthenticator.authenticateClient(request)
            }
            assertTrue {
                error.value.endsWith("cannot be used in unsigned request")
            }
        }

        @Test
        fun `if kid JOSE HEADER is missing, authentication fails`() = runTest {
            val (alg, key) = algAndKey

            // without kid JOSE Header
            val request = requestObject.signed(alg, key)

            val error = assertFailsWithError<RequestValidationError.InvalidJarJwt> {
                clientAuthenticator.authenticateClient(request)
            }
            assertTrue {
                error.cause.startsWith("Missing kid")
            }
        }

        @Test
        fun `if kid JOSE HEADER is not a DID URL, authentication fails`() = runTest {
            val (alg, key) = algAndKey
            // with a non DID URL kid JOSE Header
            val request = requestObject.signed(alg, key) { keyID("foo") }

            val error = assertFailsWithError<RequestValidationError.InvalidJarJwt> {
                clientAuthenticator.authenticateClient(request)
            }
            assertTrue {
                error.cause.endsWith("kid should be DID URL")
            }
        }

        @Test
        fun `if kid JOSE HEADER is DID URL but not a sub-resource of client_id, authentication fails`() = runTest {
            val (alg, key) = algAndKey

            // with irrelevant DID
            val request = requestObject.signed(alg, key) { keyID("did:foo:bar#1") }

            val error = assertFailsWithError<RequestValidationError.InvalidJarJwt> {
                clientAuthenticator.authenticateClient(request)
            }
            assertTrue {
                error.cause.contains("kid should be DID URL sub-resource")
            }
        }

        @Test
        fun `if resolution fails, authentication fails`() = runTest {
            val (alg, key) = algAndKey
            val failingResolution = LookupPublicKeyByDIDUrl { _ ->
                throw RuntimeException("Something happened")
            }
            val clientAuthenticator = ClientAuthenticator(
                cfg.copy(
                    supportedClientIdSchemes = listOf(
                        SupportedClientIdScheme.DID(failingResolution),
                    ),
                ),
            )

            val request = requestObject.signed(alg, key) { keyID(keyUrl.toString()) }
            assertFailsWithError<RequestValidationError.DIDResolutionFailed> {
                clientAuthenticator.authenticateClient(request)
            }
        }

        @Test
        fun `if resolution succeeds, authentication succeeds`() = runTest {
            val (alg, key) = algAndKey
            val request = requestObject.signed(alg, key) { keyID(keyUrl.toString()) }
            val client = clientAuthenticator.authenticateClient(request)
            assertEquals(AuthenticatedClient.DIDClient(clientId, key.toPublicKey()), client)
        }
    }

    @DisplayName("when handling a request with `verifier_attestation` scheme")
    @Nested
    inner class ClientAuthenticatorWhenUsingVerifierAttestationTest {

        private val clientId = "someClient"
        private val algAndKey = randomKey()

        private val cfg = SiopOpenId4VPConfig(
            supportedClientIdSchemes = listOf(
                SupportedClientIdScheme.VerifierAttestation(AttestationIssuer.verifier),
            ),
            vpConfiguration = VPConfiguration(
                vpFormats = VpFormats(VpFormat.MsoMdoc, VpFormat.SdJwtVc.ES256),
            ),
            clock = Clock.systemDefaultZone(),
        )
        private val clientAuthenticator = ClientAuthenticator(cfg)
        private val requestObject = UnvalidatedRequestObject(
            clientId = "verifier_attestation:$clientId",
        )

        @Test
        fun `if request is unsigned, authentication fails`() = runTest {
            val request = requestObject.plain()

            val error = assertFailsWithError<RequestValidationError.InvalidClientIdScheme> {
                clientAuthenticator.authenticateClient(request)
            }
            assertTrue {
                error.value.endsWith("cannot be used in unsigned request")
            }
        }

        @Test
        fun `if JAR is missing the jwt JOSE header, authentication fails`() = runTest {
            val (alg, key) = algAndKey
            val request = requestObject.signed(alg, key)
            val error = assertFailsWithError<RequestValidationError.InvalidJarJwt> {
                clientAuthenticator.authenticateClient(request)
            }
            assertTrue {
                error.cause.contains("Missing jwt JOSE Header")
            }
        }

        @Test
        fun `if JAR contains an attestation from a trusted issuer, authentication succeeds`() = runTest {
            val (alg, key) = algAndKey

            val verifierAttestation = AttestationIssuer.attestation(
                clock = cfg.clock,
                clientId = clientId,
                clientPubKey = key.toPublicJWK(),
            )
            val request = requestObject.signedWithAttestation(alg, key, verifierAttestation)

            val client = clientAuthenticator.authenticateClient(request)
            assertIs<AuthenticatedClient.Attested>(client)
            assertEquals(clientId, client.clientId)
            assertEquals(AttestationIssuer.ID, client.claims.iss)
            assertEquals(clientId, client.claims.sub)
            assertEquals(key.toPublicJWK(), client.claims.verifierPubJwk)
        }

        @Test
        fun `if JAR contains an attestation from an untrusted issuer, authentication fails`() = runTest {
            val (alg, key) = algAndKey

            val verifierAttestation = AttestationIssuer.attestation(
                clock = cfg.clock,
                clientId = clientId,
                clientPubKey = key.toPublicJWK(),
            )

            // Do not trust AttestationIssuer
            val notTrustingVerifier = object : JWSVerifier by AttestationIssuer.verifier {
                override fun verify(header: JWSHeader?, signingInput: ByteArray?, signature: Base64URL?): Boolean {
                    throw JOSEException("Fail")
                }
            }

            val clientAuthenticator = ClientAuthenticator(
                cfg.copy(
                    supportedClientIdSchemes = listOf(
                        SupportedClientIdScheme.VerifierAttestation(
                            notTrustingVerifier,
                        ),
                    ),
                ),
            )

            val request = requestObject.signedWithAttestation(alg, key, verifierAttestation)
            val error = assertFailsWithError<RequestValidationError.InvalidJarJwt> {
                clientAuthenticator.authenticateClient(request)
            }
            assertTrue { "Not trusted" in error.cause }
        }
    }
}
//
// Support
//

fun randomKey(): Pair<JWSAlgorithm, ECKey> =
    JWSAlgorithm.ES256 to ECKeyGenerator(Curve.P_256).keyUse(KeyUse.SIGNATURE).generate()

private inline fun <reified E : AuthorizationRequestError> assertFailsWithError(block: () -> Unit): E {
    val exception = assertThrows<AuthorizationRequestException>(block)
    return assertIs<E>(exception.error)
}

private fun UnvalidatedRequestObject.plain(): FetchedRequest.Plain =
    FetchedRequest.Plain(this)

private fun UnvalidatedRequestObject.signedWithAttestation(
    alg: JWSAlgorithm,
    key: JWK,
    attestation: SignedJWT,
): FetchedRequest.JwtSecured = signed(alg, key) {
    this.customParam("jwt", attestation.serialize())
}

private fun UnvalidatedRequestObject.signed(
    alg: JWSAlgorithm,
    key: JWK,
    headerCustomization: (JWSHeader.Builder).() -> Unit = {},
): FetchedRequest.JwtSecured = FetchedRequest.JwtSecured(
    clientId = checkNotNull(clientId),
    jwt = run {
        val header = with(JWSHeader.Builder(alg)) {
            type(JOSEObjectType("oauth-authz-req+jwt"))
            headerCustomization()
            build()
        }
        val claimsSet = toJWTClaimSet()
        SignedJWT(header, claimsSet).apply {
            val signer = DefaultJWSSignerFactory().createJWSSigner(key, alg)
            sign(signer)
        }
    },
)

private fun UnvalidatedRequestObject.toJWTClaimSet(): JWTClaimsSet {
    val json = Json.encodeToString(this)
    return JWTClaimsSet.parse(json)
}
