package eu.europa.ec.euidw.openid4vp

import com.nimbusds.jose.crypto.RSASSAVerifier
import com.nimbusds.jwt.SignedJWT
import com.nimbusds.oauth2.sdk.id.State
import eu.europa.ec.euidw.openid4vp.internal.ClientMetadataValidator
import eu.europa.ec.euidw.openid4vp.internal.DefaultAuthorizationResponseBuilder
import kotlinx.coroutines.runBlocking
import kotlinx.serialization.decodeFromString
import kotlinx.serialization.json.Json
import kotlin.test.Test
import kotlin.test.assertTrue
import kotlin.test.fail

class AuthorizationResponseBuilderTest {

    private val json: Json by lazy { Json { ignoreUnknownKeys = true } }

    private val walletConfig = WalletOpenId4VPConfig(
        presentationDefinitionUriSupported = true,
        supportedClientIdScheme = SupportedClientIdScheme.IsoX509,
        vpFormatsSupported = emptyList(),
        subjectSyntaxTypesSupported = listOf(
                    SubjectSyntaxType.JWKThumbprint,
                    SubjectSyntaxType.DecentralizedIdentifier.parse("did:example"),
                    SubjectSyntaxType.DecentralizedIdentifier.parse("did:key"))
    )

    private val clientMetadataStr = "{ \"jwks\": { \"keys\": [ { \"kty\": \"RSA\", \"e\": \"AQAB\", \"use\": \"sig\", \"kid\": \"a4e1bbe6-26e8-480b-a364-f43497894453\", \"iat\": 1683559586, \"n\": \"xHI9zoXS-fOAFXDhDmPMmT_UrU1MPimy0xfP-sL0Iu4CQJmGkALiCNzJh9v343fqFT2hfrbigMnafB2wtcXZeEDy6Mwu9QcJh1qLnklW5OOdYsLJLTyiNwMbLQXdVxXiGby66wbzpUymrQmT1v80ywuYd8Y0IQVyteR2jvRDNxy88bd2eosfkUdQhNKUsUmpODSxrEU2SJCClO4467fVdPng7lyzF2duStFeA2vUkZubor3EcrJ72JbZVI51YDAqHQyqKZIDGddOOvyGUTyHz9749bsoesqXHOugVXhc2elKvegwBik3eOLgfYKJwisFcrBl62k90RaMZpXCxNO4Ew\" } ] }, \"id_token_encrypted_response_alg\": \"RS256\", \"id_token_encrypted_response_enc\": \"A128CBC-HS256\", \"subject_syntax_types_supported\": [ \"urn:ietf:params:oauth:jwk-thumbprint\", \"did:example\", \"did:key\" ], \"id_token_signed_response_alg\": \"RS256\" }"

    private val clientMetaData = json.decodeFromString<ClientMetaData>(clientMetadataStr)
    private fun genState(): String {
        return State().value
    }

    private val BUILDER = DefaultAuthorizationResponseBuilder()

    @Test
    fun `id token request should produce a response with id token JWT`(): Unit = runBlocking {
        val validated = ClientMetadataValidator.validate(clientMetaData)

        val siopAuthRequestObject = ResolvedRequestObject.SiopAuthentication(
            idTokenType=  listOf(IdTokenType.AttesterSigned),
            clientMetaData=  validated.getOrThrow(),
            clientId= "https%3A%2F%2Fclient.example.org%2Fcb",
            nonce= "0S6_WzA2Mj",
            responseMode= ResponseMode.DirectPost(HttpsUrl.make("https://respond.here").getOrThrow()),
            state= genState(),
            scope= Scope.make("openid") ?: throw IllegalStateException()
        )

        val idTokenConsensus = Consensus.PositiveConsensus.IdTokenConsensus(
            idToken= SiopIdTokenBuilder.build(siopAuthRequestObject, walletConfig)
        )

        val buildResponse = BUILDER.buildResponse(siopAuthRequestObject, idTokenConsensus)

        when (buildResponse) {
            is AuthorizationResponse.DirectPost ->
                when (val data = buildResponse.data) {
                    is AuthorizationResponsePayload.SiopAuthenticationResponse ->
                        when (val idToken = data.idToken) {
                            is SignedJWT -> {
                                assertTrue("Id Token signature could not be verified") {
                                    idToken.verify(RSASSAVerifier(walletConfig.rsaJWK))
                                }
                            }
                            else -> fail("Generated token not a a signed JWT as expected")
                        }
                    else -> fail("Authorization response data not of expected type: AuthorizationResponseData.IdTokenResponseData")
                }
                else -> fail("Authorization response not of expected type: AuthorizationResponse.DirectPost")
        }

    }

}