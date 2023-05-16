package eu.europa.ec.euidw.openid4vp

import com.nimbusds.oauth2.sdk.id.State
import eu.europa.ec.euidw.openid4vp.internal.dispatch.AuthorizationResponseDispatcher
import eu.europa.ec.euidw.openid4vp.internal.dispatch.DirectPostDispatcher
import eu.europa.ec.euidw.openid4vp.internal.ktor.HttpKtorAdapter
import eu.europa.ec.euidw.openid4vp.internal.request.ClientMetadataValidator
import eu.europa.ec.euidw.openid4vp.internal.response.DefaultAuthorizationResponseBuilder
import io.ktor.client.*
import io.ktor.client.plugins.contentnegotiation.*
import io.ktor.serialization.kotlinx.json.*
import io.ktor.server.application.*
import io.ktor.server.request.*
import io.ktor.server.response.*
import io.ktor.server.routing.*
import io.ktor.server.testing.*
import kotlinx.coroutines.runBlocking
import kotlinx.serialization.decodeFromString
import kotlinx.serialization.json.Json
import org.junit.jupiter.api.Test
import java.io.Closeable
import kotlin.test.assertEquals
import kotlin.test.fail

class AuthorizationResponseDispatcherTest {

    private val json: Json by lazy { Json { ignoreUnknownKeys = true } }

    private val walletConfig = WalletOpenId4VPConfig(
        presentationDefinitionUriSupported = true,
        supportedClientIdScheme = SupportedClientIdScheme.IsoX509,
        vpFormatsSupported = emptyList(),
        subjectSyntaxTypesSupported = listOf(
            SubjectSyntaxType.JWKThumbprint,
            SubjectSyntaxType.DecentralizedIdentifier.parse("did:example"),
            SubjectSyntaxType.DecentralizedIdentifier.parse("did:key")
        )
    )

    private val clientMetadataStr =
        "{ \"jwks\": { \"keys\": [ { \"kty\": \"RSA\", \"e\": \"AQAB\", \"use\": \"sig\", \"kid\": \"a4e1bbe6-26e8-480b-a364-f43497894453\", \"iat\": 1683559586, \"n\": \"xHI9zoXS-fOAFXDhDmPMmT_UrU1MPimy0xfP-sL0Iu4CQJmGkALiCNzJh9v343fqFT2hfrbigMnafB2wtcXZeEDy6Mwu9QcJh1qLnklW5OOdYsLJLTyiNwMbLQXdVxXiGby66wbzpUymrQmT1v80ywuYd8Y0IQVyteR2jvRDNxy88bd2eosfkUdQhNKUsUmpODSxrEU2SJCClO4467fVdPng7lyzF2duStFeA2vUkZubor3EcrJ72JbZVI51YDAqHQyqKZIDGddOOvyGUTyHz9749bsoesqXHOugVXhc2elKvegwBik3eOLgfYKJwisFcrBl62k90RaMZpXCxNO4Ew\" } ] }, \"id_token_encrypted_response_alg\": \"RS256\", \"id_token_encrypted_response_enc\": \"A128CBC-HS256\", \"subject_syntax_types_supported\": [ \"urn:ietf:params:oauth:jwk-thumbprint\", \"did:example\", \"did:key\" ], \"id_token_signed_response_alg\": \"RS256\" }"

    private val clientMetaData = json.decodeFromString<ClientMetaData>(clientMetadataStr)
    private fun genState(): String {
        return State().value
    }

    @Test
    fun `dispatch direct post response`(): Unit = runBlocking {
        val validated = ClientMetadataValidator.validate(clientMetaData)

        val stateVal = genState()

        val siopAuthRequestObject = ResolvedRequestObject.SiopAuthentication(
            idTokenType = listOf(IdTokenType.AttesterSigned),
            clientMetaData = validated.getOrThrow(),
            clientId = "https%3A%2F%2Fclient.example.org%2Fcb",
            nonce = "0S6_WzA2Mj",
            responseMode = ResponseMode.DirectPost("https://respond.here".asURL().getOrThrow()),
            state = stateVal,
            scope = Scope.make("openid") ?: throw IllegalStateException()
        )

        val walletKeyPair = SiopIdTokenBuilder.randomKey()
        val idToken = SiopIdTokenBuilder.build(
            siopAuthRequestObject,
            IdToken(
                holderEmail = "foo@bar.com",
                holderName = "Foo bar"
            ),

            walletConfig,
            walletKeyPair
        )

        val idTokenConsensus = Consensus.PositiveConsensus.IdTokenConsensus(
            idToken = idToken
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
                            val idTokenTxt = formParameters["idToken"].toString()
                            val state = formParameters["state"].toString()

                            assertEquals(
                                "application/x-www-form-urlencoded; charset=UTF-8",
                                call.request.headers["Content-Type"]
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

            val DISPATCHER = TestDirectPostResponseDispatcher(managedHttpClient) { DirectPostDispatcher(it) }

            val response = DefaultAuthorizationResponseBuilder.buildResponse(siopAuthRequestObject, idTokenConsensus)

            when (response) {
                is AuthorizationResponse.DirectPost -> {
                    DISPATCHER.dispatch(response)
                }

                else -> fail("Not a direct post response")
            }
        }
    }
}


internal class TestDirectPostResponseDispatcher<in A : AuthorizationResponse.DirectPostResponse>(
    val managedHttpClient: HttpClient,
    proxyFactory: (HttpFormPost<Unit>) -> AuthorizationResponseDispatcher<A, Unit>
) : AuthorizationResponseDispatcher<A, Unit>, Closeable {

    /**
     * The actual or proxied [AuthorizationResponseDispatcher]
     */
    private val proxy: AuthorizationResponseDispatcher<A, Unit> by lazy {
        proxyFactory(HttpKtorAdapter.httpFormPost(managedHttpClient))
    }

    override suspend fun dispatch(response: A) = proxy.dispatch(response)

    override fun close() = managedHttpClient.close()


}