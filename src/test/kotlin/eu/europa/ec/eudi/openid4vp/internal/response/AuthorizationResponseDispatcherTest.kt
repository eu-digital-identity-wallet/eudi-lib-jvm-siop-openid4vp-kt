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

import com.nimbusds.oauth2.sdk.id.State
import eu.europa.ec.eudi.openid4vp.*
import eu.europa.ec.eudi.openid4vp.internal.request.ManagedClientMetaValidator
import eu.europa.ec.eudi.openid4vp.internal.request.UnvalidatedClientMetaData
import eu.europa.ec.eudi.openid4vp.internal.request.asURL
import eu.europa.ec.eudi.openid4vp.internal.request.jarmRequirement
import eu.europa.ec.eudi.prex.PresentationExchange
import eu.europa.ec.eudi.prex.PresentationSubmission
import io.ktor.client.plugins.contentnegotiation.*
import io.ktor.serialization.kotlinx.json.*
import io.ktor.server.application.*
import io.ktor.server.request.*
import io.ktor.server.response.*
import io.ktor.server.routing.*
import io.ktor.server.testing.*
import kotlinx.coroutines.test.runTest
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put
import org.junit.jupiter.api.assertDoesNotThrow
import java.io.InputStream
import java.time.Clock
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertIs

class AuthorizationResponseDispatcherTest {

    private val json: Json by lazy { Json { ignoreUnknownKeys = true } }

    private val walletConfig = SiopOpenId4VPConfig(
        supportedClientIdSchemes = listOf(SupportedClientIdScheme.X509SanDns { _ -> true }),
        clock = Clock.systemDefaultZone(),
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
    fun `dispatch direct post response`() = runTest {
        suspend fun test(state: String? = null) {
            val responseMode = ResponseMode.DirectPost("https://respond.here".asURL().getOrThrow())
            val validated = assertDoesNotThrow {
                ManagedClientMetaValidator(DefaultHttpClientFactory).validate(clientMetaData, responseMode)
            }

            val siopAuthRequestObject =
                ResolvedRequestObject.SiopAuthentication(
                    idTokenType = listOf(IdTokenType.AttesterSigned),
                    subjectSyntaxTypesSupported = validated.subjectSyntaxTypesSupported,
                    jarmRequirement = walletConfig.jarmRequirement(validated),
                    client = Client.Preregistered("https%3A%2F%2Fclient.example.org%2Fcb", "Verifier"),
                    nonce = "0S6_WzA2Mj",
                    responseMode = responseMode,
                    state = state,
                    scope = Scope.make("openid") ?: throw IllegalStateException(),
                )

            val walletKeyPair = SiopIdTokenBuilder.randomKey()
            val idToken = SiopIdTokenBuilder.build(
                siopAuthRequestObject,
                HolderInfo(
                    email = "foo@bar.com",
                    name = "Foo bar",
                ),
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
                                val stateParam = formParameters["state"]

                                assertEquals(
                                    "application/x-www-form-urlencoded",
                                    call.request.headers["Content-Type"],
                                )
                                assertEquals(state, stateParam)
                                assertEquals(idToken, idTokenTxt)

                                call.respond(buildJsonObject { put("redirect_uri", "https://foo") })
                            }
                        }
                    }
                }
                val managedHttpClient = createClient {
                    install(ContentNegotiation) {
                        json()
                    }
                }

                val dispatcher = DefaultDispatcher(walletConfig) { managedHttpClient }
                val outcome = dispatcher.dispatch(siopAuthRequestObject, idTokenConsensus)
                assertIs<DispatchOutcome.VerifierResponse>(outcome)
            }
        }

        test(genState())
        test()
    }

    @Test
    fun `dispatch vp_token with direct post`() = runTest {
        suspend fun test(state: String? = null) {
            val responseMode = ResponseMode.DirectPost("https://respond.here".asURL().getOrThrow())
            val validated = assertDoesNotThrow {
                ManagedClientMetaValidator(DefaultHttpClientFactory).validate(clientMetaData, responseMode)
            }

            val presentationDefinition =
                PresentationExchange.jsonParser.decodePresentationDefinition(load("presentation-definition/mDL-example.json")!!)
                    .fold(onSuccess = { it }, onFailure = { org.junit.jupiter.api.fail(it) })

            val presentationSubmission =
                PresentationExchange.jsonParser.decodePresentationSubmission(load("presentation-submission/example.json")!!)
                    .fold(onSuccess = { it }, onFailure = { org.junit.jupiter.api.fail(it) })

            val openId4VPAuthRequestObject =
                ResolvedRequestObject.OpenId4VPAuthorization(
                    jarmRequirement = walletConfig.jarmRequirement(validated),
                    client = Client.Preregistered("https%3A%2F%2Fclient.example.org%2Fcb", "Verifier"),
                    nonce = "0S6_WzA2Mj",
                    responseMode = responseMode,
                    state = state,
                    presentationDefinition = presentationDefinition,
                )

            val vpTokenConsensus = Consensus.PositiveConsensus.VPTokenConsensus(
                vpToken = VpToken.Generic("vp_token"),
                presentationSubmission = presentationSubmission,
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
                                val vpTokenTxt = formParameters["vp_token"].toString()
                                val presentationSubmissionStr = formParameters["presentation_submission"].toString()
                                val stateParam = formParameters["state"]

                                assertEquals(
                                    "application/x-www-form-urlencoded",
                                    call.request.headers["Content-Type"],
                                )
                                assertEquals(state, stateParam)
                                assertEquals(vpTokenTxt, "vp_token")
                                assertEquals(
                                    presentationSubmissionStr,
                                    Json.encodeToString<PresentationSubmission>(presentationSubmission),
                                )

                                call.respond(buildJsonObject { put("redirect_uri", "https://foo") })
                            }
                        }
                    }
                }
                val managedHttpClient = createClient {
                    install(ContentNegotiation) {
                        json()
                    }
                }

                val dispatcher = DefaultDispatcher(walletConfig) { managedHttpClient }
                val outcome = dispatcher.dispatch(openId4VPAuthRequestObject, vpTokenConsensus)
                assertIs<DispatchOutcome.VerifierResponse>(outcome)
            }
        }

        test(genState())
        test()
    }

    private fun load(f: String): InputStream? =
        AuthorizationResponseDispatcherTest::class.java.classLoader.getResourceAsStream(f)
}
