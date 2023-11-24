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

import com.nimbusds.jose.jwk.JWKSet
import com.nimbusds.jose.jwk.KeyUse
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator
import com.nimbusds.oauth2.sdk.id.State
import eu.europa.ec.eudi.openid4vp.internal.dispatch.DefaultDispatcher
import eu.europa.ec.eudi.openid4vp.internal.request.ClientMetadataValidator
import eu.europa.ec.eudi.openid4vp.internal.request.UnvalidatedClientMetaData
import io.ktor.client.plugins.contentnegotiation.*
import io.ktor.serialization.kotlinx.json.*
import io.ktor.server.application.*
import io.ktor.server.request.*
import io.ktor.server.response.*
import io.ktor.server.routing.*
import io.ktor.server.testing.*
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.runBlocking
import kotlinx.serialization.json.Json
import org.junit.jupiter.api.Test
import java.time.Duration
import java.util.*
import kotlin.test.assertEquals
import kotlin.test.fail

class AuthorizationResponseDispatcherTest {

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
    fun `dispatch direct post response`(): Unit = runBlocking {
        val validated = ClientMetadataValidator(Dispatchers.IO, walletConfig).validate(clientMetaData)

        val stateVal = genState()

        val siopAuthRequestObject =
            ResolvedRequestObject.SiopAuthentication(
                idTokenType = listOf(IdTokenType.AttesterSigned),
                clientMetaData = validated.getOrThrow(),
                clientId = "https%3A%2F%2Fclient.example.org%2Fcb",
                nonce = "0S6_WzA2Mj",
                responseMode = ResponseMode.DirectPost("https://respond.here".asURL().getOrThrow()),
                state = stateVal,
                scope = Scope.make("openid") ?: throw IllegalStateException(),
            )

        val walletKeyPair = SiopIdTokenBuilder.randomKey()
        val idToken = SiopIdTokenBuilder.build(
            siopAuthRequestObject,
            HolderInfo(
                email = "foo@bar.com",
                name = "Foo bar",
            ),

            walletConfig,
            walletKeyPair,
        )

        val idTokenConsensus = Consensus.PositiveConsensus.IdTokenConsensus(
            idToken = idToken,
        )

        testApplication {
            externalServices {
                hosts("https://respond.here") {
                    install(io.ktor.server.plugins.contentnegotiation.ContentNegotiation) {
                        json()
                    }
                    routing {
                        post("/") {
                            val formParameters = call.receiveParameters()
                            val idTokenTxt = formParameters["id_token"].toString()
                            val state = formParameters["state"].toString()

                            assertEquals(
                                "application/x-www-form-urlencoded; charset=UTF-8",
                                call.request.headers["Content-Type"],
                            )
                            assertEquals(stateVal, state)
                            assertEquals(idToken, idTokenTxt)

                            call.respondText("ok")
                        }
                    }
                }
            }
            val managedHttpClient = createClient {
                install(ContentNegotiation) {
                    json()
                }
            }

            val dispatcher = DefaultDispatcher(httpClientFactory = { managedHttpClient })
            when (
                val response =
                    AuthorizationResponseBuilder(walletConfig).build(siopAuthRequestObject, idTokenConsensus)
            ) {
                is AuthorizationResponse.DirectPost -> {
                    dispatcher.dispatch(response)
                }

                else -> fail("Not a direct post response")
            }
        }
    }
}
