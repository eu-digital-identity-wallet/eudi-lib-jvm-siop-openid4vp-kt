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

import com.nimbusds.jose.JOSEObjectType
import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.JWSHeader
import com.nimbusds.jose.crypto.factories.DefaultJWSSignerFactory
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
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertTrue

class RequestAuthenticatorTest

class ClientAuthenticatorTest {

    @Test
    fun `when client_id is missing, no authentication can be done`() = runTest {
        val clientAuthenticator = ClientAuthenticator(
            SiopOpenId4VPConfig(
                jarmConfiguration = JarmConfiguration.NotSupported,
                vpConfiguration = VPConfiguration(
                    presentationDefinitionUriSupported = false,
                    emptyMap(),
                ),
                supportedClientIdSchemes = listOf(
                    SupportedClientIdScheme.RedirectUri,
                ),
            ),
        )

        val request = UnvalidatedRequestObject(clientId = null).plain()

        assertFailsWithError<RequestValidationError.MissingClientId> {
            clientAuthenticator.authenticateClient(request)
        }
    }

    @Test
    fun `when scheme is missing, no authentication can be done`() = runTest {
        val clientAuthenticator = ClientAuthenticator(
            SiopOpenId4VPConfig(
                jarmConfiguration = JarmConfiguration.NotSupported,
                vpConfiguration = VPConfiguration(
                    presentationDefinitionUriSupported = false,
                    emptyMap(),
                ),
                supportedClientIdSchemes = listOf(
                    SupportedClientIdScheme.RedirectUri,
                ),
            ),
        )

        val request = UnvalidatedRequestObject(
            clientId = "foo",
            responseMode = null,
        ).plain()

        assertFailsWithError<RequestValidationError.InvalidClientIdScheme> {
            clientAuthenticator.authenticateClient(request)
        }
    }

    @Test
    fun `when scheme is wrong, no authentication can be done`() = runTest {
        val clientAuthenticator = ClientAuthenticator(
            SiopOpenId4VPConfig(
                jarmConfiguration = JarmConfiguration.NotSupported,
                vpConfiguration = VPConfiguration(
                    presentationDefinitionUriSupported = false,
                    emptyMap(),
                ),
                supportedClientIdSchemes = listOf(
                    SupportedClientIdScheme.RedirectUri,
                ),
            ),
        )

        val request = UnvalidatedRequestObject(
            clientId = "foo",
            responseMode = "bar",
        ).plain()

        assertFailsWithError<RequestValidationError.InvalidClientIdScheme> {
            clientAuthenticator.authenticateClient(request)
        }
    }

    @Test
    fun `when scheme is redirect_uri, client_id is URI and request is not signed, we have authentication`() =
        runTest {
            val clientAuthenticator = ClientAuthenticator(
                SiopOpenId4VPConfig(
                    jarmConfiguration = JarmConfiguration.NotSupported,
                    vpConfiguration = VPConfiguration(
                        presentationDefinitionUriSupported = false,
                        emptyMap(),
                    ),
                    supportedClientIdSchemes = listOf(
                        SupportedClientIdScheme.RedirectUri,
                    ),
                ),
            )

            val clientId = URI.create("http://localhost:8080")
            val request = UnvalidatedRequestObject(
                clientId = clientId.toString(),
                clientIdScheme = "redirect_uri",
            ).plain()

            val client = clientAuthenticator.authenticateClient(request)
            assertEquals(AuthenticatedClient.RedirectUri(clientId), client)
        }

    @Test
    fun `when scheme is redirect_uri signed request fail`() = runTest {
        val clientAuthenticator = ClientAuthenticator(
            SiopOpenId4VPConfig(
                jarmConfiguration = JarmConfiguration.NotSupported,
                vpConfiguration = VPConfiguration(
                    presentationDefinitionUriSupported = false,
                    emptyMap(),
                ),
                supportedClientIdSchemes = listOf(
                    SupportedClientIdScheme.RedirectUri,
                ),
            ),
        )

        val clientId = URI.create("http://localhost:8080")
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

    @Test
    fun `when scheme is DID cannot be used with unsigned requests`() = runTest {
        val clientId = DID.parse("did:example:123").getOrThrow()
        val keyUrl = AbsoluteDIDUrl.parse("$clientId#01").getOrThrow()
        val (alg, key) = randomKey()

        val clientAuthenticator = ClientAuthenticator(
            SiopOpenId4VPConfig(
                jarmConfiguration = JarmConfiguration.NotSupported,
                vpConfiguration = VPConfiguration(
                    presentationDefinitionUriSupported = false,
                    emptyMap(),
                ),
                supportedClientIdSchemes = listOf(
                    SupportedClientIdScheme.DID { url ->
                        assertEquals(keyUrl.uri, url)
                        key.toPublicKey()
                    },
                ),
            ),
        )

        val request = UnvalidatedRequestObject(
            clientId = clientId.toString(),
            clientIdScheme = "did",
        ).plain()

        val error = assertFailsWithError<RequestValidationError.InvalidClientIdScheme> {
            clientAuthenticator.authenticateClient(request)
        }
        assertTrue {
            error.value.endsWith("cannot be used in unsigned request")
        }
    }

    @Test
    fun `when scheme is DID`() = runTest {
        val clientId = DID.parse("did:example:123").getOrThrow()
        val keyUrl = AbsoluteDIDUrl.parse("$clientId#01").getOrThrow()
        val (alg, key) = randomKey()

        val clientAuthenticator = ClientAuthenticator(
            SiopOpenId4VPConfig(
                jarmConfiguration = JarmConfiguration.NotSupported,
                vpConfiguration = VPConfiguration(
                    presentationDefinitionUriSupported = false,
                    emptyMap(),
                ),
                supportedClientIdSchemes = listOf(
                    SupportedClientIdScheme.DID { url ->
                        assertEquals(keyUrl.uri, url)
                        key.toPublicKey()
                    },
                ),
            ),
        )
        run {
            // without kid JOSE Header
            val request = UnvalidatedRequestObject(
                clientId = clientId.toString(),
                clientIdScheme = "did",
            ).signed(alg, key)

            val error = assertFailsWithError<RequestValidationError.InvalidJarJwt> {
                clientAuthenticator.authenticateClient(request)
            }
            assertTrue {
                error.cause.startsWith("Missing kid")
            }
        }
        run {
            // with a non DID URL kid JOSE Header
            val request = UnvalidatedRequestObject(
                clientId = clientId.toString(),
                clientIdScheme = "did",
            ).signed(alg, key) { keyID("foo") }

            val error = assertFailsWithError<RequestValidationError.InvalidJarJwt> {
                clientAuthenticator.authenticateClient(request)
            }
            assertTrue {
                error.cause.endsWith("kid should be DID URL")
            }
        }
        run {
            // with a irrelevant DID
            val request = UnvalidatedRequestObject(
                clientId = clientId.toString(),
                clientIdScheme = "did",
            ).signed(alg, key) { keyID("did:foo:bar#1") }

            val error = assertFailsWithError<RequestValidationError.InvalidJarJwt> {
                clientAuthenticator.authenticateClient(request)
            }
            assertTrue {
                error.cause.contains("kid should be DID URL sub-resource")
            }
        }

        run {
            val request = UnvalidatedRequestObject(
                clientId = clientId.toString(),
                clientIdScheme = "did",
            ).signed(alg, key) { keyID(keyUrl.toString()) }

            val client = clientAuthenticator.authenticateClient(request)
            assertEquals(AuthenticatedClient.DIDClient(clientId, key.toPublicKey()), client)
        }
    }
}

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
