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
import com.nimbusds.jose.crypto.ECDHEncrypter
import com.nimbusds.jose.crypto.ECDSASigner
import com.nimbusds.jose.jwk.Curve
import com.nimbusds.jose.jwk.ECKey
import com.nimbusds.jose.jwk.JWKSet
import com.nimbusds.jose.jwk.gen.ECKeyGenerator
import com.nimbusds.jwt.JWTClaimsSet
import com.nimbusds.jwt.SignedJWT
import eu.europa.ec.eudi.openid4vp.*
import io.ktor.client.*
import io.ktor.client.engine.mock.*
import io.ktor.client.request.forms.*
import io.ktor.http.*
import kotlinx.coroutines.test.runTest
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import org.junit.jupiter.api.Test
import java.net.URI
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertNull

internal class RequestFetcherTest {

    @Test
    fun `fetch signed request object`() = runTest {
        val clientId = "verifier"
        val config = config(clientId, EncryptionRequirement.NotRequired)
        val requestUri = URI.create("https://verifier/signed-request")

        lateinit var signedRequest: SignedJWT
        val engine = MockEngine { request ->
            assertEquals(HttpMethod.Post, request.method)
            assertEquals(requestUri, request.url.toURI())
            assertEquals(listOf("application/oauth-authz-req+jwt", "application/jwt"), request.headers.getAll(HttpHeaders.Accept))

            val body = assertIs<FormDataContent>(request.body)

            val walletMetadata = Json.decodeFromString<JsonObject>(assertIs<String>(body.formData[OpenId4VPSpec.WALLET_METADATA]))
            assertNull(walletMetadata["jwks"])
            assertNull(walletMetadata["authorization_encryption_alg_values_supported"])
            assertNull(walletMetadata["authorization_encryption_enc_values_supported"])

            val walletNonce = assertIs<String>(body.formData[OpenId4VPSpec.WALLET_NONCE])

            signedRequest = createSignedRequestObject(clientId, walletNonce)

            respond(
                content = signedRequest.serialize(),
                status = HttpStatusCode.OK,
                headers = headersOf(HttpHeaders.ContentType to listOf("application/oauth-authz-req+jwt")),
            )
        }
        val client = HttpClient(engine = engine)

        val fetcher = RequestFetcher(client, config)
        val request = UnvalidatedRequest.JwtSecured.PassByReference(
            clientId = clientId,
            jwtURI = requestUri.toURL(),
            requestURIMethod = RequestUriMethod.POST,
        )

        val fetchedRequest = assertIs<FetchedRequest.JwtSecured>(fetcher.fetchRequest(request))
        assertEquals(signedRequest.serialize(), fetchedRequest.jwt.serialize())
    }

    @Test
    fun `fetch encrypted and signed request object`() = runTest {
        val clientId = "verifier"
        val config = config(
            clientId,
            EncryptionRequirement.Required(
                supportedEncryptionAlgorithms = listOf(JWEAlgorithm.ECDH_ES_A256KW),
                supportedEncryptionMethods = listOf(EncryptionMethod.A256GCM),
                ephemeralEncryptionKeyCurve = Curve.P_521,
            ),
        )
        val requestUri = URI.create("https://verifier/encrypted-request")

        lateinit var signedRequest: SignedJWT
        val engine = MockEngine { request ->
            assertEquals(HttpMethod.Post, request.method)
            assertEquals(requestUri, request.url.toURI())
            assertEquals(listOf("application/oauth-authz-req+jwt", "application/jwt"), request.headers.getAll(HttpHeaders.Accept))

            val body = assertIs<FormDataContent>(request.body)
            val walletMetadata = Json.decodeFromString<JsonObject>(assertIs<String>(body.formData[OpenId4VPSpec.WALLET_METADATA]))

            val encryptionKeys = JWKSet.parse(Json.encodeToString(assertIs<JsonObject>(walletMetadata["jwks"])))
            assertEquals(1, encryptionKeys.size())
            val encryptionKey = assertIs<ECKey>(encryptionKeys.keys.first())
            assertEquals(Curve.P_521, encryptionKey.curve)
            assertEquals(
                JsonArray(listOf(JsonPrimitive(JWEAlgorithm.ECDH_ES_A256KW.name))),
                walletMetadata["authorization_encryption_alg_values_supported"],
            )
            assertEquals(
                JsonArray(listOf(JsonPrimitive(EncryptionMethod.A256GCM.name))),
                walletMetadata["authorization_encryption_enc_values_supported"],
            )

            val walletNonce = assertIs<String>(body.formData[OpenId4VPSpec.WALLET_NONCE])

            signedRequest = createSignedRequestObject(clientId, walletNonce)
            val encryptedRequest =
                createEncryptedRequestObject(signedRequest, encryptionKey, JWEAlgorithm.ECDH_ES_A256KW, EncryptionMethod.A256GCM)
            respond(
                content = encryptedRequest.serialize(),
                status = HttpStatusCode.OK,
                headers = headersOf(HttpHeaders.ContentType to listOf("application/oauth-authz-req+jwt")),
            )
        }
        val client = HttpClient(engine = engine)

        val fetcher = RequestFetcher(client, config)
        val request = UnvalidatedRequest.JwtSecured.PassByReference(
            clientId = clientId,
            jwtURI = requestUri.toURL(),
            requestURIMethod = RequestUriMethod.POST,
        )

        val fetchedRequest = assertIs<FetchedRequest.JwtSecured>(fetcher.fetchRequest(request))
        assertEquals(signedRequest.serialize(), fetchedRequest.jwt.serialize())
    }
}

private fun config(clientId: String, jarEncryptionRequirement: EncryptionRequirement): SiopOpenId4VPConfig =
    SiopOpenId4VPConfig(
        jarConfiguration = JarConfiguration(
            supportedAlgorithms = JWSAlgorithm.Family.EC.toList() - JWSAlgorithm.ES256K,
            supportedRequestUriMethods = SupportedRequestUriMethods.Post(
                includeWalletMetadata = true,
                jarEncryption = jarEncryptionRequirement,
                useWalletNonce = NonceOption.Use(),
            ),
        ),
        vpConfiguration = VPConfiguration(
            vpFormats = VpFormats(VpFormat.SdJwtVc.ES256, VpFormat.MsoMdoc.ES256),
        ),
        supportedClientIdSchemes = listOf(SupportedClientIdScheme.Preregistered(PreregisteredClient(clientId, clientId))),
    )

private fun createSignedRequestObject(clientId: String, walletNonce: String): SignedJWT =
    SignedJWT(
        JWSHeader.Builder(JWSAlgorithm.ES256).build(),
        JWTClaimsSet.Builder()
            .claim("client_id", clientId)
            .claim(OpenId4VPSpec.WALLET_NONCE, walletNonce)
            .build(),
    ).apply {
        sign(ECDSASigner(ECKeyGenerator(Curve.P_256).generate()))
    }

private fun createEncryptedRequestObject(
    signedRequestObject: SignedJWT,
    encryptionKey: ECKey,
    encryptionAlgorithm: JWEAlgorithm,
    encryptionMethod: EncryptionMethod,
): JWEObject =
    JWEObject(
        JWEHeader.Builder(encryptionAlgorithm, encryptionMethod)
            .contentType("JWT")
            .build(),
        Payload(signedRequestObject),
    ).apply {
        encrypt(ECDHEncrypter(encryptionKey))
    }
