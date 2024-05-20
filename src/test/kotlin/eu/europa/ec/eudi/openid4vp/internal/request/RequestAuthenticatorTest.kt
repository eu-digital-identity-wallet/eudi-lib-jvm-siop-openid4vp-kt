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
import com.nimbusds.jose.crypto.factories.DefaultJWSVerifierFactory
import com.nimbusds.jose.jwk.Curve
import com.nimbusds.jose.jwk.ECKey
import com.nimbusds.jose.jwk.JWK
import com.nimbusds.jose.jwk.KeyUse
import com.nimbusds.jose.jwk.gen.ECKeyGenerator
import com.nimbusds.jwt.JWTClaimsSet
import com.nimbusds.jwt.SignedJWT
import eu.europa.ec.eudi.openid4vp.*
import eu.europa.ec.eudi.openid4vp.internal.AbsoluteDIDUrl
import eu.europa.ec.eudi.openid4vp.internal.DID
import kotlinx.coroutines.test.runTest
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import org.junit.jupiter.api.assertThrows
import java.net.URI
import java.time.Clock
import java.util.Date
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertTrue

class RequestAuthenticatorTest

//
// Common tests
//

class ClientAuthenticatorCommonTest {

    private val cfg = SiopOpenId4VPConfig(
        supportedClientIdSchemes = listOf(
            SupportedClientIdScheme.RedirectUri,
        ),
    )
    private val clientAuthenticator = ClientAuthenticator(cfg)

    @Test
    fun `when client_id is missing, no authentication can be done`() = runTest {
        val request = UnvalidatedRequestObject(clientId = null).plain()
        assertFailsWithError<RequestValidationError.MissingClientId> {
            clientAuthenticator.authenticateClient(request)
        }
    }

    @Test
    fun `when scheme is missing, no authentication can be done`() = runTest {
        val request = UnvalidatedRequestObject(
            clientId = "foo",
            clientIdScheme = null,
        ).plain()

        assertFailsWithError<RequestValidationError.InvalidClientIdScheme> {
            clientAuthenticator.authenticateClient(request)
        }
    }

    @Test
    fun `when scheme is wrong, no authentication can be done`() = runTest {
        val request = UnvalidatedRequestObject(
            clientId = "foo",
            responseMode = "bar",
        ).plain()

        assertFailsWithError<RequestValidationError.InvalidClientIdScheme> {
            clientAuthenticator.authenticateClient(request)
        }
    }
}

//
// Redirect URI tests
//

class ClientAuthenticatorWhenUsingRedirectUriTest {
    private val clientId = URI.create("http://localhost:8080")
    private val cfg = SiopOpenId4VPConfig(
        supportedClientIdSchemes = listOf(
            SupportedClientIdScheme.RedirectUri,
        ),
    )
    private val clientAuthenticator = ClientAuthenticator(cfg)

    @Test
    fun `when scheme is redirect_uri, client_id is URI and request is not signed, we have authentication`() =
        runTest {
            val request = UnvalidatedRequestObject(
                clientId = clientId.toString(),
                clientIdScheme = "redirect_uri",
            ).plain()

            val client = clientAuthenticator.authenticateClient(request)
            assertEquals(AuthenticatedClient.RedirectUri(clientId), client)
        }

    @Test
    fun `when scheme is redirect_uri signed request fail`() = runTest {
        val (alg, key) = randomKey()
        val request = UnvalidatedRequestObject(
            clientId = clientId.toString(),
            clientIdScheme = "redirect_uri",
        ).signed(alg, key)

        val error = assertFailsWithError<RequestValidationError.InvalidClientIdScheme> {
            clientAuthenticator.authenticateClient(request)
        }
        assertEquals("RedirectUri cannot be used in signed request", error.value)
    }
}

//
// DID scheme tests
//

class ClientAuthenticatorWhenUsingDIDTest {
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
    )
    private val clientAuthenticator = ClientAuthenticator(cfg)
    private val requestObject = UnvalidatedRequestObject(
        clientId = clientId.toString(),
        clientIdScheme = "did",
    )

    @Test
    fun `when scheme is DID cannot be used with unsigned requests`() = runTest {
        val request = requestObject.plain()

        val error = assertFailsWithError<RequestValidationError.InvalidClientIdScheme> {
            clientAuthenticator.authenticateClient(request)
        }
        assertTrue {
            error.value.endsWith("cannot be used in unsigned request")
        }
    }

    @Test
    fun `when scheme is DID a kid must be present`() = runTest {
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
    fun `when scheme is DID kid must be DID URL `() = runTest {
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
    fun `when scheme is DID kid should be sub-resource of client_id `() = runTest {
        val (alg, key) = algAndKey

        // with an irrelevant DID
        val request = requestObject.signed(alg, key) { keyID("did:foo:bar#1") }

        val error = assertFailsWithError<RequestValidationError.InvalidJarJwt> {
            clientAuthenticator.authenticateClient(request)
        }
        assertTrue {
            error.cause.contains("kid should be DID URL sub-resource")
        }
    }

    @Test
    fun `when scheme is DID if resolution fails, authentication fails`() = runTest {
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
    fun `when scheme is DID if resolution succeeds, must authenticate`() = runTest {
        val (alg, key) = algAndKey
        val request = requestObject.signed(alg, key) { keyID(keyUrl.toString()) }
        val client = clientAuthenticator.authenticateClient(request)
        assertEquals(AuthenticatedClient.DIDClient(clientId, key.toPublicKey()), client)
    }
}

//
// Verifier Attestation Tests
//

class ClientAuthenticatorWhenUsingVerifierAttestationTest {

    private val clientId = "someClient"
    private val algAndKey = randomKey()

    private object AttestationIssuer {
        val id = "Attestation Issuer"
        val algAndKey = randomKey()

        val verifier: JWSVerifier = run {
            val (alg, key) = algAndKey
            val h = JWSHeader.Builder(alg).build()
            DefaultJWSVerifierFactory().createJWSVerifier(h, key.toPublicKey())
        }

        fun attestation(
            clock: Clock,
            verifier: String,
            verifierJwk: JWK,
        ): SignedJWT {
            val (alg, key) = algAndKey
            val signer = DefaultJWSSignerFactory().createJWSSigner(key, alg)
            val header = JWSHeader.Builder(alg)
                .type(JOSEObjectType("verifier-attestation+jwt"))
                .build()
            val now = clock.instant()
            val iat = Date.from(now)
            val exp = Date.from(now.plusSeconds(60))
            val claimSet = with(JWTClaimsSet.Builder()) {
                issuer(id)
                subject(verifier)
                issueTime(iat)
                expirationTime(exp)
                claim("cnf", mapOf("jwk" to verifierJwk.toPublicJWK().toJSONObject()))
                build()
            }

            return SignedJWT(header, claimSet).apply { sign(signer) }
        }
    }

    private val cfg = SiopOpenId4VPConfig(
        supportedClientIdSchemes = listOf(
            SupportedClientIdScheme.VerifierAttestation(AttestationIssuer.verifier),
        ),
    )
    private val clientAuthenticator = ClientAuthenticator(cfg)
    private val requestObject = UnvalidatedRequestObject(
        clientId = clientId,
        clientIdScheme = "verifier_attestation",
    )

    @Test
    fun `when scheme is verifier_attestation cannot be used with unsigned requests`() = runTest {
        val request = requestObject.plain()

        val error = assertFailsWithError<RequestValidationError.InvalidClientIdScheme> {
            clientAuthenticator.authenticateClient(request)
        }
        assertTrue {
            error.value.endsWith("cannot be used in unsigned request")
        }
    }

    @Test
    fun `when scheme is verifier_attestation with a JAR missing jwt JOSE, should fail`() = runTest {
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
    fun `when scheme is verifier_attestation `() = runTest {
        val (alg, key) = algAndKey

        val verifierAttestation = AttestationIssuer.attestation(
            clock = Clock.systemDefaultZone(),
            verifier = clientId,
            verifierJwk = key.toPublicJWK(),
        )
        val request = requestObject.signedWithAttestation(alg, key, verifierAttestation)

        val client = clientAuthenticator.authenticateClient(request)
        assertIs<AuthenticatedClient.Attested>(client)
        assertEquals(clientId, client.clientId)
        assertEquals(AttestationIssuer.id, client.claims.iss)
        assertEquals(clientId, client.claims.sub)
        assertEquals(key.toPublicJWK(), client.claims.verifierPubJwk)
    }

    private fun UnvalidatedRequestObject.signedWithAttestation(
        alg: JWSAlgorithm,
        key: JWK,
        attestation: SignedJWT,
    ) =
        signed(alg, key) {
            this.customParam("jwt", attestation.serialize())
        }
}

//
// Support
//

private fun randomKey(): Pair<JWSAlgorithm, ECKey> =
    JWSAlgorithm.ES256 to ECKeyGenerator(Curve.P_256).keyUse(KeyUse.SIGNATURE).generate()

private inline fun <reified E : AuthorizationRequestError> assertFailsWithError(block: () -> Unit): E {
    val exception = assertThrows<AuthorizationRequestException>(block)
    return assertIs<E>(exception.error)
}

private fun UnvalidatedRequestObject.plain(): FetchedRequest.Plain =
    FetchedRequest.Plain(this)

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
