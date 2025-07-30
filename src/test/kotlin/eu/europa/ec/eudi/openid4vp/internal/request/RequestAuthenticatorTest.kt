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
import eu.europa.ec.eudi.openid4vp.internal.*
import kotlinx.coroutines.test.runTest
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import org.junit.jupiter.api.DisplayName
import org.junit.jupiter.api.Nested
import org.junit.jupiter.api.assertThrows
import java.net.URI
import java.time.Clock
import kotlin.test.*

@DisplayName("In case of request is coming through HTTP")
class ClientAuthenticatorOverHTTPTest {

    @DisplayName("when handling a request")
    @Nested
    inner class ClientAuthenticatorCommonTest {

        private val cfg = SiopOpenId4VPConfig(
            supportedClientIdPrefixes = listOf(
                SupportedClientIdPrefix.RedirectUri,
            ),
            vpConfiguration = VPConfiguration(
                vpFormatsSupported = VpFormatsSupported(
                    VpFormatsSupported.SdJwtVc.HAIP,
                    VpFormatsSupported.MsoMdoc(
                        issuerAuthAlgorithms = listOf(CoseAlgorithm(-7)),
                        deviceAuthAlgorithms = listOf(CoseAlgorithm(-7)),
                    ),
                ),
            ),
            clock = Clock.systemDefaultZone(),
        )
        private val clientAuthenticator = ClientAuthenticator(cfg)

        @Test
        fun `if client_id is missing, authentication fails`() = runTest {
            val request = UnvalidatedRequestObject(clientId = null).unsigned()
            assertFailsWithError<RequestValidationError.MissingClientId> {
                clientAuthenticator.authenticateClientOverHttp(request)
            }
        }

        @Test
        fun `if client_id prefix is invalid, authentication fails`() = runTest {
            val request = UnvalidatedRequestObject(
                clientId = "bar:foo",
                responseMode = "bar",
            ).unsigned()

            assertFailsWithError<RequestValidationError.InvalidClientIdPrefix> {
                clientAuthenticator.authenticateClientOverHttp(request)
            }
        }
    }

    @DisplayName("when handling a request with `redirect_uri` prefix")
    @Nested
    inner class ClientAuthenticatorWhenUsingRedirectUriTest {
        private val clientId = URI.create("http://localhost:8080")
        private val cfg = SiopOpenId4VPConfig(
            supportedClientIdPrefixes = listOf(
                SupportedClientIdPrefix.RedirectUri,
            ),
            vpConfiguration = VPConfiguration(
                vpFormatsSupported = VpFormatsSupported(
                    VpFormatsSupported.SdJwtVc.HAIP,
                    VpFormatsSupported.MsoMdoc(
                        issuerAuthAlgorithms = listOf(CoseAlgorithm(-7)),
                        deviceAuthAlgorithms = listOf(CoseAlgorithm(-7)),
                    ),
                ),
            ),
        )
        private val clientAuthenticator = ClientAuthenticator(cfg)

        @Test
        fun `if request is not signed, authentication succeeds`() =
            runTest {
                val request = UnvalidatedRequestObject(
                    clientId = "redirect_uri:$clientId",
                ).unsigned()

                val client = clientAuthenticator.authenticateClientOverHttp(request)
                assertEquals(AuthenticatedClient.RedirectUri(clientId), client)
            }

        @Test
        fun `if  request is signed, authentication fails`() = runTest {
            val (alg, key) = randomKey()
            val request = UnvalidatedRequestObject(
                clientId = "redirect_uri:$clientId",
            ).signed(alg, key)

            val error = assertFailsWithError<RequestValidationError.InvalidClientIdPrefix> {
                clientAuthenticator.authenticateClientOverHttp(request)
            }
            assertEquals("RedirectUri cannot be used in signed request", error.value)
        }
    }

    @DisplayName("when handling a request with `decentralized_identifier` prefix")
    @Nested
    inner class ClientAuthenticatorWhenUsingDIDTest {
        private val originalClientId = DID.parse("did:example:123").getOrThrow()
        private val clientId = "decentralized_identifier:$originalClientId"
        private val keyUrl = AbsoluteDIDUrl.parse("$originalClientId#01").getOrThrow()
        private val algAndKey = randomKey()
        private val cfg = SiopOpenId4VPConfig(
            supportedClientIdPrefixes = listOf(
                SupportedClientIdPrefix.DecentralizedIdentifier { url ->
                    assertEquals(keyUrl.uri, url)
                    algAndKey.second.toPublicKey()
                },
            ),
            vpConfiguration = VPConfiguration(
                vpFormatsSupported = VpFormatsSupported(
                    VpFormatsSupported.SdJwtVc.HAIP,
                    VpFormatsSupported.MsoMdoc(
                        issuerAuthAlgorithms = listOf(CoseAlgorithm(-7)),
                        deviceAuthAlgorithms = listOf(CoseAlgorithm(-7)),
                    ),
                ),
            ),
        )
        private val clientAuthenticator = ClientAuthenticator(cfg)
        private val requestObject = UnvalidatedRequestObject(
            clientId = clientId,
        )

        @Test
        fun `if request is not signed, authentication fails`() = runTest {
            val request = requestObject.unsigned()

            val error = assertFailsWithError<RequestValidationError.InvalidClientIdPrefix> {
                clientAuthenticator.authenticateClientOverHttp(request)
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
                clientAuthenticator.authenticateClientOverHttp(request)
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
                clientAuthenticator.authenticateClientOverHttp(request)
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
                clientAuthenticator.authenticateClientOverHttp(request)
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
                    supportedClientIdPrefixes = listOf(
                        SupportedClientIdPrefix.DecentralizedIdentifier(failingResolution),
                    ),
                ),
            )

            val request = requestObject.signed(alg, key) { keyID(keyUrl.toString()) }
            assertFailsWithError<RequestValidationError.DIDResolutionFailed> {
                clientAuthenticator.authenticateClientOverHttp(request)
            }
        }

        @Test
        fun `if resolution succeeds, authentication succeeds`() = runTest {
            val (alg, key) = algAndKey
            val request = requestObject.signed(alg, key) { keyID(keyUrl.toString()) }
            val client = clientAuthenticator.authenticateClientOverHttp(request)
            assertEquals(AuthenticatedClient.DecentralizedIdentifier(originalClientId, key.toPublicKey()), client)
        }
    }

    @DisplayName("when handling a request with `verifier_attestation` prefix")
    @Nested
    inner class ClientAuthenticatorWhenUsingVerifierAttestationTest {

        private val clientId = "someClient"
        private val algAndKey = randomKey()

        private val cfg = SiopOpenId4VPConfig(
            supportedClientIdPrefixes = listOf(
                SupportedClientIdPrefix.VerifierAttestation(AttestationIssuer.verifier),
            ),
            vpConfiguration = VPConfiguration(
                vpFormatsSupported = VpFormatsSupported(
                    VpFormatsSupported.SdJwtVc.HAIP,
                    VpFormatsSupported.MsoMdoc(
                        issuerAuthAlgorithms = listOf(CoseAlgorithm(-7)),
                        deviceAuthAlgorithms = listOf(CoseAlgorithm(-7)),
                    ),
                ),
            ),
            clock = Clock.systemDefaultZone(),
        )
        private val clientAuthenticator = ClientAuthenticator(cfg)
        private val requestObject = UnvalidatedRequestObject(
            clientId = "verifier_attestation:$clientId",
        )

        @Test
        fun `if request is unsigned, authentication fails`() = runTest {
            val request = requestObject.unsigned()

            val error = assertFailsWithError<RequestValidationError.InvalidClientIdPrefix> {
                clientAuthenticator.authenticateClientOverHttp(request)
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
                clientAuthenticator.authenticateClientOverHttp(request)
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

            val client = clientAuthenticator.authenticateClientOverHttp(request)
            assertIs<AuthenticatedClient.VerifierAttestation>(client)
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
                    supportedClientIdPrefixes = listOf(
                        SupportedClientIdPrefix.VerifierAttestation(
                            notTrustingVerifier,
                        ),
                    ),
                ),
            )

            val request = requestObject.signedWithAttestation(alg, key, verifierAttestation)
            val error = assertFailsWithError<RequestValidationError.InvalidJarJwt> {
                clientAuthenticator.authenticateClientOverHttp(request)
            }
            assertTrue { "Not trusted" in error.cause }
        }
    }
}

@DisplayName("In case of request is coming through DC API")
class RequestAuthenticatorOverDCApiTest {

    private val didAlgAndKey = randomKey()

    private val x509SanDnsSupportedPrefix = SupportedClientIdPrefix.X509SanDns({ _ -> true })
    private val didSupportedScheme = SupportedClientIdPrefix.DecentralizedIdentifier({ _ -> didAlgAndKey.second.toPublicKey() })

    private val cfg = SiopOpenId4VPConfig(
        vpConfiguration = VPConfiguration(
            vpFormatsSupported = VpFormatsSupported(
                VpFormatsSupported.SdJwtVc.HAIP,
                VpFormatsSupported.MsoMdoc(
                    issuerAuthAlgorithms = listOf(CoseAlgorithm(-7)),
                    deviceAuthAlgorithms = listOf(CoseAlgorithm(-7)),
                ),
            ),
        ),
        supportedClientIdPrefixes = listOf(x509SanDnsSupportedPrefix, didSupportedScheme),
        signedRequestConfiguration = SignedRequestConfiguration(
            supportedAlgorithms = JWSAlgorithm.Family.EC.toList() - JWSAlgorithm.ES256K,
            supportedRequestUriMethods = SupportedRequestUriMethods.Default,
            multiSignedRequestsPolicy = MultiSignedRequestsPolicy.ExpectPrefix(ClientIdPrefix.DecentralizedIdentifier),
        ),
    )

    @DisplayName("when handling a request")
    @Nested
    inner class AuthenticatorCommonTest {

        private val clientAuthenticator = ClientAuthenticator(cfg)
        private val requestAuthenticator = RequestAuthenticator(cfg, createHttpClient())

        @Test
        fun `if request is unsinged the resolved client must be Origin`() = runTest {
            val request = UnvalidatedRequestObject().unsigned()

            val (authenticateClient, _) = clientAuthenticator.authenticateClientOverDCApi("test_origin", request)
            assertIs<AuthenticatedClient.Origin>(authenticateClient)
            assertTrue("test_origin" == authenticateClient.clientId)
        }

        @Test
        fun `if request is signed, it must contain expected_origins`() = runTest {
            val originalClientId = DID.parse("did:example:123").getOrThrow()
            val clientId = "decentralized_identifier:$originalClientId"
            val (alg, key) = didAlgAndKey

            var request = UnvalidatedRequestObject(
                clientId = clientId,
            ).signed(alg, key) { keyID("$originalClientId#key-0") }

            var error = assertFailsWith<AuthorizationRequestException> {
                requestAuthenticator.authenticateRequestOverDCApi("test_origin", request)
            }
            assertIs<RequestValidationError.MissingExpectedOrigins>(error.error)

            request = UnvalidatedRequestObject(
                clientId = clientId,
                expectedOrigins = listOf("test_origin", "test_origin_alt"),
            ).signed(alg, key) { keyID("$originalClientId#key-0") }

            error = assertFailsWith<AuthorizationRequestException> {
                requestAuthenticator.authenticateRequestOverDCApi("origin", request)
            }
            assertIs<RequestValidationError.UnexpectedOrigin>(error.error)

            request = UnvalidatedRequestObject(
                clientId = clientId,
                expectedOrigins = listOf("test_origin", "test_origin_alt"),
            ).signed(alg, key) { keyID("$originalClientId#key-0") }

            val (authenticateClient, _) = requestAuthenticator.authenticateRequestOverDCApi("test_origin", request)
            assertIs<AuthenticatedClient.DecentralizedIdentifier>(authenticateClient)
            assertTrue(originalClientId == authenticateClient.client)
            assertTrue(didAlgAndKey.second.toPublicKey() == authenticateClient.publicKey)
        }
    }

    @DisplayName("when handling a multi-signed request")
    @Nested
    inner class ClientAuthenticatorMultiSignedRequestsTest {

        private val clientAuthenticator = ClientAuthenticator(cfg)

        @Test
        fun `if expected scheme is found request client is properly authenticated`() = runTest {
            val request = UnvalidatedRequestObject(
                expectedOrigins = listOf("test_origin", "test_origin_alt"),
            ).multiSigned(
                listOf(didSigner(), verifierAttestationSigner()),
            )
            val (authenticateClient, _) = clientAuthenticator.authenticateClientOverDCApi("test_origin", request)
            assertIs<AuthenticatedClient.DecentralizedIdentifier>(authenticateClient)
        }

        @Test
        fun `if request expected scheme is not found in request fail`() = runTest {
            val request = UnvalidatedRequestObject(
                expectedOrigins = listOf("test_origin", "test_origin_alt"),
            ).multiSigned(
                listOf(verifierAttestationSigner()),
            )
            assertFailsWithError<RequestValidationError.NoMatchingPrefixInMultiSignedRequest> {
                clientAuthenticator.authenticateClientOverDCApi("test_origin", request)
            }
        }

        private fun didSigner(): SchemeSigner {
            val (alg2, key2) = didAlgAndKey
            val originalClientId = DID.parse("did:example:123").getOrThrow()
            val clientId = "decentralized_identifier:$originalClientId"
            return SchemeSigner(alg2, key2) {
                customParam("client_id", clientId)
                keyID("did:example:123#key-1")
            }
        }

        private fun verifierAttestationSigner(): SchemeSigner {
            val (alg, key) = randomKey()
            val verifierAttestation = AttestationIssuer.attestation(
                clock = cfg.clock,
                clientId = "verifier_attestation:http://example.com",
                clientPubKey = key.toPublicJWK(),
            )
            return SchemeSigner(alg, key) {
                customParam("client_id", "verifier_attestation:http://www.example.com")
                customParam("jwt", verifierAttestation.serialize())
            }
        }

        @Test
        fun `can create a multi-signed request`() = runTest {
            val originalClientId = DID.parse("did:example:123").getOrThrow()

            // Create two signers with different keys
            val (alg1, key1) = randomKey()
            val (alg2, key2) = randomKey()

            val signer1 = SchemeSigner(alg1, key1) { keyID(originalClientId.toString()) }
            val signer2 = SchemeSigner(alg2, key2) { keyID(originalClientId.toString()) }

            // Create a request object with client ID and expected origins
            val clientId = "decentralized_identifier:$originalClientId"
            val request = UnvalidatedRequestObject(
                clientId = clientId,
                expectedOrigins = listOf("test_origin", "test_origin_alt"),
            ).multiSigned(listOf(signer1, signer2))

            // Verify that the request is a ReceivedRequest.Signed with a JwsJson.General
            assertIs<ReceivedRequest.Signed>(request)
            assertIs<JwsJson.General>(request.jwsJson)

            // Verify that the JwsJson.General has two signatures
            val jwsJson = request.jwsJson
            assertEquals(2, jwsJson.signatures.size)

            // Verify that the signatures have the correct protected headers
            val signature1 = jwsJson.signatures[0]
            val signature2 = jwsJson.signatures[1]

            assertNotNull(signature1.protected)
            assertNotNull(signature2.protected)
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

private fun UnvalidatedRequestObject.unsigned(): ReceivedRequest.Unsigned =
    ReceivedRequest.Unsigned(this)

private fun UnvalidatedRequestObject.signedWithAttestation(
    alg: JWSAlgorithm,
    key: JWK,
    attestation: SignedJWT,
): ReceivedRequest.Signed = signed(alg, key) {
    this.customParam("jwt", attestation.serialize())
}

private fun UnvalidatedRequestObject.signed(
    alg: JWSAlgorithm,
    key: JWK,
    headerCustomization: (JWSHeader.Builder).() -> Unit = {},
): ReceivedRequest.Signed {
    val header = with(JWSHeader.Builder(alg)) {
        type(JOSEObjectType(OpenId4VPSpec.AUTHORIZATION_REQUEST_OBJECT_TYPE))
        headerCustomization()
        build()
    }
    val claimsSet = toJWTClaimSet()
    val jwt = SignedJWT(header, claimsSet).apply {
        val signer = DefaultJWSSignerFactory().createJWSSigner(key, alg)
        sign(signer)
    }
    return ReceivedRequest.Signed(jwt)
}

private fun UnvalidatedRequestObject.multiSigned(
    signers: List<SchemeSigner>,
): ReceivedRequest.Signed {
    require(signers.isNotEmpty()) { "At least one signer is required" }

    // Convert the request object to JWT claims
    val claimsSet = toJWTClaimSet()

    // Create the payload as Base64UrlNoPadding
    val payloadJson = claimsSet.toString()
    val payloadBase64 = base64UrlNoPadding.encode(payloadJson.encodeToByteArray())
    val payload = Base64UrlNoPadding.invoke(payloadBase64).getOrThrow()

    // Create signatures for each signer
    val signatures = signers.map { signer ->
        // Create a SignedJWT for this signer
        val header = with(JWSHeader.Builder(signer.alg)) {
            type(JOSEObjectType(OpenId4VPSpec.AUTHORIZATION_REQUEST_OBJECT_TYPE))
            signer.headerCustomization(this)
            build()
        }

        // Sign the JWT
        val jwt = SignedJWT(header, claimsSet).apply {
            val jwsSigner = DefaultJWSSignerFactory().createJWSSigner(signer.key, signer.alg)
            sign(jwsSigner)
        }

        // Extract the parts from the signed JWT
        val parts = jwt.serialize().split(".")
        val protectedHeader = Base64UrlNoPadding(parts[0]).getOrThrow()
        val signature = Base64UrlNoPadding(parts[2]).getOrThrow()

        // Create a Signature object
        Signature(protected = protectedHeader, signature = signature)
    }

    // Create a JwsJson.General object with the payload and signatures
    val jwsJson = JwsJson.General(payload = payload, signatures = signatures)

    // Return a ReceivedRequest.Signed with the JwsJson.General object
    return ReceivedRequest.Signed(jwsJson)
}

private class SchemeSigner(
    val alg: JWSAlgorithm,
    val key: JWK,
    val headerCustomization: (JWSHeader.Builder).() -> Unit,
)

private fun UnvalidatedRequestObject.toJWTClaimSet(): JWTClaimsSet {
    val json = Json.encodeToString(this)
    return JWTClaimsSet.parse(json)
}
