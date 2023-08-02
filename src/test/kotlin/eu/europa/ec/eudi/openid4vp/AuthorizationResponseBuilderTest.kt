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
package eu.europa.ec.eudi.openid4vp

import com.nimbusds.jose.crypto.RSASSAVerifier
import com.nimbusds.jose.jwk.JWKSet
import com.nimbusds.jose.jwk.KeyUse
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator
import com.nimbusds.jwt.SignedJWT
import com.nimbusds.oauth2.sdk.id.State
import eu.europa.ec.eudi.openid4vp.internal.request.ClientMetadataValidator
import eu.europa.ec.eudi.prex.Id
import eu.europa.ec.eudi.prex.PresentationDefinition
import eu.europa.ec.eudi.prex.PresentationSubmission
import junit.framework.TestCase.assertFalse
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.runBlocking
import kotlinx.serialization.json.Json
import org.junit.jupiter.api.Assertions
import java.time.Duration
import java.util.*
import kotlin.test.Test
import kotlin.test.assertNotNull
import kotlin.test.assertTrue
import kotlin.test.fail

class AuthorizationResponseBuilderTest {

    private val json: Json by lazy { Json { ignoreUnknownKeys = true } }

    private val signingKey = RSAKeyGenerator(2048)
        .keyUse(KeyUse.SIGNATURE) // indicate the intended use of the key (optional)
        .keyID(UUID.randomUUID().toString()) // give the key a unique ID (optional)
        .issueTime(Date(System.currentTimeMillis())) // issued-at timestamp (optional)
        .generate()

    private val walletConfig = WalletOpenId4VPConfig(
        presentationDefinitionUriSupported = true,
        supportedClientIdSchemes = listOf(SupportedClientIdScheme.IsoX509),
        vpFormatsSupported = emptyList(),
        subjectSyntaxTypesSupported = listOf(
            SubjectSyntaxType.JWKThumbprint,
            SubjectSyntaxType.DecentralizedIdentifier.parse("did:example"),
            SubjectSyntaxType.DecentralizedIdentifier.parse("did:key"),
        ),
        signingKey = signingKey,
        signingKeySet = JWKSet(signingKey),
        idTokenTTL = Duration.ofMinutes(10),
        preferredSubjectSyntaxType = SubjectSyntaxType.JWKThumbprint,
        decentralizedIdentifier = "DID:example:12341512#$",
        authorizationSigningAlgValuesSupported = emptyList(),
        authorizationEncryptionAlgValuesSupported = emptyList(),
        authorizationEncryptionEncValuesSupported = emptyList(),
    )

    private val clientMetadataStr =
        """
            { "jwks": { "keys": [ { "kty": "RSA", "e": "AQAB", "use": "sig", "kid": "a4e1bbe6-26e8-480b-a364-f43497894453", "iat": 1683559586, "n": "xHI9zoXS-fOAFXDhDmPMmT_UrU1MPimy0xfP-sL0Iu4CQJmGkALiCNzJh9v343fqFT2hfrbigMnafB2wtcXZeEDy6Mwu9QcJh1qLnklW5OOdYsLJLTyiNwMbLQXdVxXiGby66wbzpUymrQmT1v80ywuYd8Y0IQVyteR2jvRDNxy88bd2eosfkUdQhNKUsUmpODSxrEU2SJCClO4467fVdPng7lyzF2duStFeA2vUkZubor3EcrJ72JbZVI51YDAqHQyqKZIDGddOOvyGUTyHz9749bsoesqXHOugVXhc2elKvegwBik3eOLgfYKJwisFcrBl62k90RaMZpXCxNO4Ew" } ] }, "id_token_encrypted_response_alg": "RS256", "id_token_encrypted_response_enc": "A128CBC-HS256", "subject_syntax_types_supported": [ "urn:ietf:params:oauth:jwk-thumbprint", "did:example", "did:key" ], "id_token_signed_response_alg": "RS256" }
        """.trimIndent()

    private val clientMetaData = json.decodeFromString<UnvalidatedClientMetaData>(clientMetadataStr)
    private fun genState(): String {
        return State().value
    }

    @Test
    fun `id token request should produce a response with id token JWT`(): Unit = runBlocking {
        val validated = ClientMetadataValidator(Dispatchers.IO, walletConfig).validate(clientMetaData)

        val siopAuthRequestObject =
            ResolvedRequestObject.SiopAuthentication(
                idTokenType = listOf(IdTokenType.AttesterSigned),
                clientMetaData = validated.getOrThrow(),
                clientId = "https%3A%2F%2Fclient.example.org%2Fcb",
                nonce = "0S6_WzA2Mj",
                responseMode = ResponseMode.DirectPost("https://respond.here".asURL().getOrThrow()),
                state = genState(),
                scope = Scope.make("openid") ?: throw IllegalStateException(),
            )

        val rsaJWK = SiopIdTokenBuilder.randomKey()

        val idTokenConsensus = Consensus.PositiveConsensus.IdTokenConsensus(
            idToken = SiopIdTokenBuilder.build(
                request = siopAuthRequestObject,
                holderInfo = HolderInfo("foo@bar.com", "foo bar"),
                rsaJWK = rsaJWK,
                walletConfig = walletConfig,
            ),
        )

        val response = AuthorizationResponseBuilder.make(walletConfig).build(siopAuthRequestObject, idTokenConsensus)

        when (response) {
            is AuthorizationResponse.DirectPost ->
                when (val data = response.data) {
                    is AuthorizationResponsePayload.SiopAuthentication -> {
                        val idToken = data.idToken
                        assertTrue("Id Token signature could not be verified") {
                            SignedJWT.parse(idToken).verify(RSASSAVerifier(rsaJWK))
                        }
                    }

                    else -> fail("Authorization response data not of expected type: AuthorizationResponseData.IdTokenResponseData")
                }

            else -> fail("Authorization response not of expected type: AuthorizationResponse.DirectPost")
        }
    }

    @Test
    fun `when direct_post jwt, builder should return DirectPostJwt with JarmSpec of correct type`(): Unit = runBlocking {
        val clientMetadataStr =
            """
                { "jwks": { "keys": [{"kty":"EC","use":"enc","crv":"P-256","kid":"123","x":"h9vfgIOK_KS40MNbX6Rpnc5-IkM8Tqvoc_6bG4nD610","y":"Yvo8GGg6axZhyikq8YqeqFk8apbp0PmjKo0cNZwkSDw","alg":"ECDH-ES"}, { "kty": "RSA", "e": "AQAB", "use": "sig", "kid": "a4e1bbe6-26e8-480b-a364-f43497894453", "iat": 1683559586, "n": "xHI9zoXS-fOAFXDhDmPMmT_UrU1MPimy0xfP-sL0Iu4CQJmGkALiCNzJh9v343fqFT2hfrbigMnafB2wtcXZeEDy6Mwu9QcJh1qLnklW5OOdYsLJLTyiNwMbLQXdVxXiGby66wbzpUymrQmT1v80ywuYd8Y0IQVyteR2jvRDNxy88bd2eosfkUdQhNKUsUmpODSxrEU2SJCClO4467fVdPng7lyzF2duStFeA2vUkZubor3EcrJ72JbZVI51YDAqHQyqKZIDGddOOvyGUTyHz9749bsoesqXHOugVXhc2elKvegwBik3eOLgfYKJwisFcrBl62k90RaMZpXCxNO4Ew" } ] }, "id_token_encrypted_response_alg": "RS256", "id_token_encrypted_response_enc": "A128CBC-HS256", "subject_syntax_types_supported": [ "urn:ietf:params:oauth:jwk-thumbprint", "did:example", "did:key" ], "id_token_signed_response_alg": "RS256","authorization_encrypted_response_alg":"ECDH_ES", "authorization_encrypted_response_enc":"A256GCM" }
            """.trimIndent()
        val clientMetaDataDecoded = json.decodeFromString<UnvalidatedClientMetaData>(clientMetadataStr)
        val clientMetadataValidated = ClientMetadataValidator(Dispatchers.IO, walletConfig).validate(clientMetaDataDecoded)

        assertFalse(clientMetadataValidated.isSuccess)
        if (!clientMetadataValidated.isSuccess){
            return@runBlocking
        }

        val resolvedRequest =
            ResolvedRequestObject.OpenId4VPAuthorization(
                presentationDefinition = PresentationDefinition(
                    id = Id("pdId"),
                    inputDescriptors = emptyList(),
                ),
                clientMetaData = clientMetadataValidated.getOrThrow(),
                clientId = "https%3A%2F%2Fclient.example.org%2Fcb",
                nonce = "0S6_WzA2Mj",
                responseMode = ResponseMode.DirectPostJwt("https://respond.here".asURL().getOrThrow()),
                state = genState(),
            )

        val vpTokenConsensus = Consensus.PositiveConsensus.VPTokenConsensus(
            "dummy_vp_token",
            PresentationSubmission(Id("psId"), Id("pdId"), emptyList()),
        )
        val response = AuthorizationResponseBuilder.make(walletConfig).build(resolvedRequest, vpTokenConsensus)

        assertTrue("Response not of the expected type DirectPostJwt") { response is AuthorizationResponse.DirectPostJwt }
        assertNotNull((response as AuthorizationResponse.DirectPostJwt).jarmSpec)
        assertTrue(response.jarmSpec.jarmOption is JarmOption.EncryptedResponse)


    }
}
