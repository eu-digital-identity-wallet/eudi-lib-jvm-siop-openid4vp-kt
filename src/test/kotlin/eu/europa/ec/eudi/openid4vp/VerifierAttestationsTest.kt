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

import com.nimbusds.jose.EncryptionMethod
import com.nimbusds.jose.JWEAlgorithm
import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.jwk.Curve
import com.nimbusds.jwt.SignedJWT
import eu.europa.ec.eudi.openid4vp.RequestValidationError.InvalidVerifierAttestations
import eu.europa.ec.eudi.openid4vp.dcql.*
import eu.europa.ec.eudi.openid4vp.internal.jsonSupport
import eu.europa.ec.eudi.openid4vp.internal.request.requestObject
import io.ktor.client.*
import io.ktor.client.call.*
import io.ktor.client.engine.okhttp.*
import io.ktor.client.plugins.contentnegotiation.*
import io.ktor.client.request.*
import io.ktor.http.*
import io.ktor.serialization.kotlinx.json.*
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.flow
import kotlinx.coroutines.flow.mapNotNull
import kotlinx.coroutines.test.runTest
import kotlinx.coroutines.withContext
import kotlinx.serialization.Required
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.jsonPrimitive
import org.junit.jupiter.api.Test
import java.time.Clock
import kotlin.test.Ignore
import kotlin.test.assertNotNull

class VerifierAttestationsTest {

    val sampleJarJwt = """
            eyJ0eXAiOiJvYXV0aC1hdXRoei1yZXErand0IiwiYWxnIjoiRVMyNTYiLCJ4NWMiOlsiTUlJQjdEQ0NBWk9nQXdJQkFnSVVIajhxc0JpSFVadm5FcEdlcDk3OE5ZUU5qcE13Q2dZSUtvWkl6ajBFQXdJd0d6RVpNQmNHQTFVRUF3d1FSMlZ5YldGdUlGSmxaMmx6ZEhKaGNqQWVGdzB5TlRBME1URXhOelV5TXpOYUZ3MHlOakEwTVRFeE56VXlNek5hTUJJeEVEQU9CZ05WQkFNTUIwUmxiVzhnVWxBd1dUQVRCZ2NxaGtqT1BRSUJCZ2dxaGtqT1BRTUJCd05DQUFRVUpQR2hhYVQ4SmErdHBuVlVqVXdoWlZxM0xEVjc1RWNCWEdMcGFXL2c0Z2h4ZkRUUVpSTS8zVEQyZ0dWTm5KTjZtNy8vMEZaZzlsemxLVmJtSXMxR280RzlNSUc2TUFrR0ExVWRFd1FDTUFBd0N3WURWUjBQQkFRREFnV2dNQk1HQTFVZEpRUU1NQW9HQ0NzR0FRVUZCd01CTUJvR0ExVWRFUVFUTUJHQ0QyWjFibXRsTFhkaGJHeGxkQzVrWlRBdkJnTlZIUjhFS0RBbU1DU2dJcUFnaGg1b2RIUndjem92TDJaMWJtdGxMWGRoYkd4bGRDNWtaUzlqWVM5amNtd3dIUVlEVlIwT0JCWUVGSzRZS0VSa1pYUCt0RzllRFJhVmRFQko2aDIyTUI4R0ExVWRJd1FZTUJhQUZNeG5LTGtHaWZiVEtyeGJHWGNGWEs2UkZRZDNNQW9HQ0NxR1NNNDlCQU1DQTBjQU1FUUNJUUQrWVhmaWkwdHprZEZ4M2lZYTdpc2F2YjFzVmgzaWNDU2IrQkJ4UkxKdTdnSWZUdDIzRGtoZkNhLzVvZ0FUR3c1YXhtWGFPTjFKUFI4OVA2OFVNUFBXTnc9PSJdfQ.eyJyZXNwb25zZV90eXBlIjoidnBfdG9rZW4iLCJjbGllbnRfaWQiOiJ4NTA5X3Nhbl9kbnM6ZnVua2Utd2FsbGV0LmRlIiwicmVzcG9uc2VfdXJpIjoiaHR0cHM6Ly9mdW5rZS13YWxsZXQuZGUvb2lkNHZwL3Jlc3BvbnNlIiwicmVzcG9uc2VfbW9kZSI6ImRpcmVjdF9wb3N0Lmp3dCIsIm5vbmNlIjoiODYwMzAzNDA3NTI4MzI0NTI2ODcxMzEzIiwiZGNxbF9xdWVyeSI6eyJjcmVkZW50aWFscyI6W3siaWQiOiJwaWQiLCJmb3JtYXQiOiJkYytzZC1qd3QiLCJtZXRhIjp7InZjdF92YWx1ZXMiOlsiaHR0cHM6Ly9kZW1vLnBpZC1pc3N1ZXIuYnVuZGVzZHJ1Y2tlcmVpLmRlL2NyZWRlbnRpYWxzL3BpZC8xLjAiLCJ1cm46ZXUuZXVyb3BhLmVjLmV1ZGk6cGlkOjEiXX0sImNsYWltcyI6W3sicGF0aCI6WyJmYW1pbHlfbmFtZSJdfSx7InBhdGgiOlsiZ2l2ZW5fbmFtZSJdfV19XX0sImNsaWVudF9tZXRhZGF0YSI6eyJqd2tzIjp7ImtleXMiOlt7Imt0eSI6IkVDIiwiY3J2IjoiUC0yNTYiLCJ4IjoiemtUTGZhXzU2cU5qa3c4aUZRbEV0XzRxMWdSSmk1Skl3dVVzREg3NEwxQSIsInkiOiItS21aNmFCR24tVXllck9PaHNnODEwNjFKOUlJdnNaNmR6dTdBWTNnc1djIiwia2lkIjoiekRuYWV3WVVGQWtVTDZIYTVRMUg5eG84a01zR0c4Y0dOWTNhWDlHN3BrdUtpMVdUOSIsInVzZSI6ImVuYyJ9XX0sInZwX2Zvcm1hdHMiOnsibXNvX21kb2MiOnsiYWxnIjpbIkVkRFNBIiwiRVMyNTYiLCJFUzM4NCJdfSwidmMrc2Qtand0Ijp7ImtiLWp3dF9hbGdfdmFsdWVzIjpbIkVkRFNBIiwiRVMyNTYiLCJFUzM4NCIsIkVTMjU2SyJdLCJzZC1qd3RfYWxnX3ZhbHVlcyI6WyJFZERTQSIsIkVTMjU2IiwiRVMzODQiLCJFUzI1NksiXX0sImRjK3NkLWp3dCI6eyJrYi1qd3RfYWxnX3ZhbHVlcyI6WyJFZERTQSIsIkVTMjU2IiwiRVMzODQiLCJFUzI1NksiXSwic2Qtand0X2FsZ192YWx1ZXMiOlsiRWREU0EiLCJFUzI1NiIsIkVTMzg0IiwiRVMyNTZLIl19fSwiYXV0aG9yaXphdGlvbl9lbmNyeXB0ZWRfcmVzcG9uc2VfYWxnIjoiRUNESC1FUyIsImF1dGhvcml6YXRpb25fZW5jcnlwdGVkX3Jlc3BvbnNlX2VuYyI6IkEyNTZHQ00iLCJjbGllbnRfbmFtZSI6Ikdlcm1hbiBSZWdpc3RyYXIiLCJyZXNwb25zZV90eXBlc19zdXBwb3J0ZWQiOlsidnBfdG9rZW4iXX0sInN0YXRlIjoiNzY0MTQzNTE2OTMzMzIwNTQwNzQ0NTg0IiwiYXVkIjoiaHR0cHM6Ly9mdW5rZS13YWxsZXQuZGUiLCJleHAiOjE3NDY1Mzg0ODQsImlhdCI6MTc0NjUzODE4NCwidmVyaWZpZXJfYXR0ZXN0YXRpb25zIjpbeyJmb3JtYXQiOiJqd3QiLCJkYXRhIjoiZXlKMGVYQWlPaUp5WXkxeWNDdHFkM1FpTENKNE5XTWlPbHNpVFVsSlFtUlVRME5CVW5WblFYZEpRa0ZuU1ZWSWMxTnRZa2QxVjBGV1dsWllhbkZ2YVdSeFFWWkRiRWQ0TkZsM1EyZFpTVXR2V2tsNmFqQkZRWGRKZDBkNlJWcE5RbU5IUVRGVlJVRjNkMUZTTWxaNVlsZEdkVWxHU214YU1teDZaRWhLYUdOcVFXVkdkekI1VGxSQmVrMTZRWGhQVkZVMFRsUkdZVVozTUhsT2FrRjZUWHBCZUU5VVZUUk9WRVpoVFVKemVFZFVRVmhDWjA1V1FrRk5UVVZGWkd4amJURm9ZbWxDVTFwWFpIQmpNMUo1V1ZoSmQxZFVRVlJDWjJOeGFHdHFUMUJSU1VKQ1oyZHhhR3RxVDFCUlRVSkNkMDVEUVVGVFVWZERSVk5HWkRCWmQyMDVjMHM0TjFoNGNYaEVVRFIzVDBGaFpFVkxaMk5hUmxaWU4yNXdaVE5CVEVaclltcHpXRmxhU25OVVIyaFdjREFyUWpWYWRGVmhiekpPYzNsNlNrTkxlbTVRZDFSNk1uZEtZMjk2TUhkUGVrRmhRbWRPVmtoU1JVVkZla0ZTWjJjNWJXUlhOWEphVXpFeldWZDRjMXBZVVhWYVIxVjNTRkZaUkZaU01FOUNRbGxGUmsxNGJrdE1hMGRwWm1KVVMzSjRZa2RZWTBaWVN6WlNSbEZrTTAxQmIwZERRM0ZIVTAwME9VSkJUVU5CTUdkQlRVVlZRMGxSUkRSU2FVeEtaWFZXUkhKRlNGTjJhMUJwVUdaQ2RrMTRRVmhTUXpaUWRVVjRiM0JWUjBOR1pHWk9URkZKWjBoSFUyRTFkVFZhY1ZWMFEzSnVUV2xoUldGblpVODNNWEpxZWtKc2IzWXdXVlZJTkNzMlJVeHBiMWs5SWwwc0ltRnNaeUk2SWtWVE1qVTJJbjAuZXlKd2NtbDJZV041WDNCdmJHbGplU0k2SW1oMGRIQnpPaTh2WlhoaGJYQnNaUzVqYjIwdmNISnBkbUZqZVMxd2IyeHBZM2tpTENKd2RYSndiM05sSWpwYmV5SnNiMk5oYkdVaU9pSmxiaTFWVXlJc0ltNWhiV1VpT2lKVWJ5QnlaV2RwYzNSbGNpQmhJRzVsZHlCMWMyVnlJbjFkTENKamIyNTBZV04wSWpwN0luZGxZbk5wZEdVaU9pSm9kSFJ3Y3pvdkwyVjRZVzF3YkdVdVkyOXRMMk52Ym5SaFkzUWlMQ0psTFcxaGFXd2lPaUpqYjI1MFlXTjBRR1Y0WVcxd2JHVXVZMjl0SWl3aWNHaHZibVVpT2lJck1USXpORFUyTnpnNU1DSjlMQ0pqY21Wa1pXNTBhV0ZzY3lJNlczc2lhV1FpT2lKd2FXUWlMQ0ptYjNKdFlYUWlPaUprWXl0elpDMXFkM1FpTENKdFpYUmhJanA3SW5aamRGOTJZV3gxWlhNaU9sc2lhSFIwY0hNNkx5OWtaVzF2TG5CcFpDMXBjM04xWlhJdVluVnVaR1Z6WkhKMVkydGxjbVZwTG1SbEwyTnlaV1JsYm5ScFlXeHpMM0JwWkM4eExqQWlMQ0oxY200NlpYVXVaWFZ5YjNCaExtVmpMbVYxWkdrNmNHbGtPakVpWFgwc0ltTnNZV2x0Y3lJNlczc2ljR0YwYUNJNld5Sm1ZVzFwYkhsZmJtRnRaU0pkZlN4N0luQmhkR2dpT2xzaVoybDJaVzVmYm1GdFpTSmRmVjE5WFN3aVkzSmxaR1Z1ZEdsaGJGOXpaWFJ6SWpwYmV5SnZjSFJwYjI1eklqcGJXeUp3YVdRaVhWMHNJbkpsY1hWcGNtVmtJanAwY25WbExDSndkWEp3YjNObElqcGJleUpzYjJOaGJHVWlPaUpsYmkxVlV5SXNJbTVoYldVaU9pSlVieUJ5WldkcGMzUmxjaUJoSUc1bGR5QjFjMlZ5SW4xZGZWMHNJbk4xWWlJNklrTk9QVVJsYlc4Z1VsQWlMQ0pxZEdraU9pSTBNakZoTWpnek9TMWtOak14TFRReU1ETXRPVEJrTXkxbE4yWTJaREpsWVdGbU9EUWlMQ0p6ZEdGMGRYTWlPbnNpYzNSaGRIVnpYMnhwYzNRaU9uc2lhV1I0SWpvME9EQXdMQ0oxY21raU9pSm9kSFJ3Y3pvdkwyWjFibXRsTFhkaGJHeGxkQzVrWlM5emRHRjBkWE10YldGdVlXZGxiV1Z1ZEM5emRHRjBkWE10YkdsemRDSjlmU3dpY0hWaWJHbGpYMkp2WkhraU9tWmhiSE5sTENKbGJuUnBkR3hsYldWdWRITWlPbHRkTENKelpYSjJhV05sY3lJNlcxMTkucjNURHpNR2JyelVLX0xyTld1XzFJNGYwY0VMZFRoWnZSSE5IQl9ROGVQTWhiRlB4TlE3akdBcktJWDRfTzUyOUQxWDJoVWV1dVNneVc2MVNWTkwwakEifV19.0jJsucCHdX4g24KPVrE3Etu8l4jwWvNda1RfHQNtSBpvjECG_DdkqmjLjtNq0HsNk2enMK-BxDSj9Ev5t2P1Pg
    """.trimIndent()
    val sampleRequestUri =
        """
            openid4vp://?client_id=x509_san_dns%3Afunke-wallet.de&request_uri=https%3A%2F%2Ffunke-wallet.de%2Foid4vp%2Fdraft-24%2Fvalid-request
        """.trimIndent()

    @Test
    @Ignore
    fun testParsing() = runTest {
        val unvalidatedRequestObject = SignedJWT.parse(sampleJarJwt).requestObject().also { println(it) }
        val attestation = run {
            val verifierAttestationsArray = assertNotNull(unvalidatedRequestObject.verifierAttestations)
            VerifierAttestations.fromJson(verifierAttestationsArray).getOrThrow()
        }.value.firstOrNull() { it.format == "jwt" }

        assertNotNull(attestation)

        val relyingPartyCertificateMetadata =
            createHttpClient().use { httpClient ->
                with(FunkeVerifierAttestations) {
                    attestation.relyingPartyCertificateMetadata(httpClient).getOrThrow()
                }
            }

        println(relyingPartyCertificateMetadata)
    }

    @Test
    fun funkeVP() = runTest {
        val openIdVp =
            SiopOpenId4Vp.funke(walletCfg, { createHttpClient() }) { dcql, rpMetadata ->
                // add policy
                // DCQL is from authorization request
                // rpMetadata is from funke verifier
                true
            }

        generateUri(10)
            .mapNotNull { uri ->
                println("Processing uri: $uri ...")
                runCatching {  openIdVp.resolveRequestUri(uri) }.recover { println(it.message); null }
            }
            .collect { resolution -> println(resolution) }

    }


    private fun generateUri(size: Int): Flow<String> =

        flow {
            createHttpClient().use { httpClient ->
                (0..size).forEach { _ ->
                    val uri =
                        httpClient.get("https://funke-wallet.de/oid4vp?oid4vp-version=draft-24&request=valid-request&response=uri")
                            .body<JsonObject>()["request"]?.jsonPrimitive?.content

                    emit(checkNotNull(uri) { "Oops" })
                }
            }
        }


    fun doTest(uri: String) = runTest {


        openIdVp.resolveRequestUri(uri)

    }

    val openIdVp by lazy {
        SiopOpenId4Vp.funke(walletCfg, { createHttpClient() }) { dcql, rpMetadata ->
            // add policy
            // DCQL is from authorization request
            // rpMetadata is from funke verifier
            true
        }
    }
    private val walletCfg =
        SiopOpenId4VPConfig(
            vpConfiguration = VPConfiguration(
                vpFormats = VpFormats(VpFormat.SdJwtVc.ES256, VpFormat.MsoMdoc.ES256),
                supportedTransactionDataTypes = listOf(
                    SupportedTransactionDataType(
                        TransactionDataType("eu.europa.ec.eudi.family-name-presentation"),
                        setOf(HashAlgorithm.SHA_256),
                    ),
                ),
            ),
            jarConfiguration = JarConfiguration(
                supportedAlgorithms = listOf(JWSAlgorithm.ES256),
                supportedRequestUriMethods = SupportedRequestUriMethods.Both(
                    SupportedRequestUriMethods.Post(
                        jarEncryption = EncryptionRequirement.Required(
                            supportedEncryptionAlgorithms = EncryptionRequirement.Required.SUPPORTED_ENCRYPTION_ALGORITHMS,
                            supportedEncryptionMethods = EncryptionRequirement.Required.SUPPORTED_ENCRYPTION_METHODS,
                            ephemeralEncryptionKeyCurve = Curve.P_521,
                        ),
                    ),
                ),
            ),
            jarmConfiguration = JarmConfiguration.Encryption(
                supportedAlgorithms = listOf(JWEAlgorithm.ECDH_ES),
                supportedMethods = listOf(EncryptionMethod.A128CBC_HS256, EncryptionMethod.A256GCM),
            ),
            supportedClientIdSchemes = listOf(
                SupportedClientIdScheme.X509SanDns({ _ -> true }),
            ),
            clock = Clock.systemDefaultZone(),
        )


    private fun createHttpClient(): HttpClient = HttpClient(OkHttp) {
        engine {
            config {
                sslSocketFactory(SslSettings.sslContext().socketFactory, SslSettings.trustManager())
                hostnameVerifier(SslSettings.hostNameVerifier())
            }
        }
        install(ContentNegotiation) { json() }

        expectSuccess = true
    }
}

interface FunkeVerifierAttestations {

    companion object : FunkeVerifierAttestations {

        @Serializable
        data class VerifierAttestationPayload(
            val sub: String,
            val jti: String,
            @SerialName("status") val status: StatusWrapper,
            @SerialName("privacy_policy") val privatePolicy: String,
            @SerialName("purpose") val purpose: List<LocalizedText>,
            @SerialName("contact") val contact: ContactInfo,
            @SerialName(OpenId4VPSpec.DCQL_CREDENTIALS) @Required val credentials: Credentials,
            @SerialName(OpenId4VPSpec.DCQL_CREDENTIAL_SETS) val credentialSets: CredentialSets? = null,
            @SerialName("public_body") val publicBody: Boolean,
            @SerialName("entitlements") val entitlements: List<String>,
            @SerialName("services") val services: List<String>,
        )

        @Serializable
        data class LocalizedText(
            val locale: String,
            val name: String,
        )

        @Serializable
        data class ContactInfo(
            @SerialName("website") val website: String,
            @SerialName("e-mail") val email: String,
            @SerialName("phone") val phone: String,
        )

        @Serializable
        data class StatusWrapper(
            val status_list: StatusList,
        )

        @Serializable
        data class StatusList(
            val idx: Int,
            val uri: String,
        )

        @Serializable
        data class RelyingPartyInfo(
            val id: String,
            val name: String,
            val EORI: String? = null,
            val NTR: String? = null,
            val LEI: String? = null,
            val VAT: String? = null,
            val EX: String? = null,
            val TAX: String? = null,
            val EUID: String? = null,
            val distinguishedName: String? = null,
            val user: String? = null,
        )

        @Serializable
        data class AttestationMetadata(
            val id: String,
            val jwt: String,
            val intendedUse: IntendedUse,
            val revoked: Boolean? = null,
        )

        @Serializable
        data class IntendedUse(
            val purpose: List<LocalizedText>,
            val credentials: List<CredentialQueryWithoutId>,
            val credentialSet: CredentialSets? = null,
        )

        // TODO Why id is not advertised?
        @Serializable
        data class CredentialQueryWithoutId(
            @SerialName(OpenId4VPSpec.DCQL_ID) val id: QueryId? = null,
            @SerialName(OpenId4VPSpec.DCQL_FORMAT) @Required val format: Format,
            @SerialName(OpenId4VPSpec.DCQL_META) val meta: JsonObject? = null,
            @SerialName(OpenId4VPSpec.DCQL_CLAIMS) val claims: List<ClaimsQuery>? = null,
            @SerialName(OpenId4VPSpec.DCQL_CLAIM_SETS) val claimSets: List<ClaimSet>? = null,
        )
    }

    suspend fun VerifierAttestations.Attestation.relyingPartyCertificateMetadata(client: HttpClient): Result<AttestationMetadata> =
        client.runCatching {
            require(format == "jwt") { "Attestation format must be jwt" }
            val attestationJwt = data.jsonPrimitive.content
            client.resolveAttestationJwt(attestationJwt).getOrThrow()
        }

    suspend fun HttpClient.resolveAttestationJwt(jwtAttestation: String): Result<AttestationMetadata> = runCatching {
        val (signedJwt, payload) = jwtAndPayload(jwtAttestation).getOrThrow()
        // TODO verify signature
        val rpInfo = fetchRpIds(payload.sub).firstOrNull()
        checkNotNull(rpInfo) { "RP info not found for sub: ${payload.sub}" }
        val relyingPartyCertificateMetadata = fetchRpCertificates(rpInfo.id).firstOrNull()
        checkNotNull(relyingPartyCertificateMetadata) { "Relying party certificates not found for id: ${rpInfo.id}" }
    }

    suspend fun jwtAndPayload(jwt: String): Result<Pair<SignedJWT, VerifierAttestationPayload>> =
        withContext(Dispatchers.IO) {
            runCatching {
                val signedJWT = SignedJWT.parse(jwt)
                val data = jsonSupport.decodeFromString<VerifierAttestationPayload>(signedJWT.jwtClaimsSet.toString())
                signedJWT to data
            }
        }

    /**
     * This method gets the RP ID using the SUB value of the relying party.
     */
    suspend fun HttpClient.fetchRpIds(sub: String): List<RelyingPartyInfo> {
        val url = buildUrl {
            protocol = URLProtocol.HTTPS
            host = "funke-wallet.de"
            pathSegments = listOf("relying-parties")
            parameters.append("name", sub.removePrefix("CN="))
        }
        return get(url).body()
    }

    /**
     * This method gets the RP certificates using the RP ID.
     */
    suspend fun HttpClient.fetchRpCertificates(rpId: String): List<AttestationMetadata> {
        val url = "https://funke-wallet.de/relying-parties/$rpId/registration-certificates"
        return get(url).body()
    }
}

fun SiopOpenId4Vp.Companion.funke(
    siopOpenId4VPConfig: SiopOpenId4VPConfig,
    httpClientFactory: KtorHttpClientFactory = DefaultHttpClientFactory,
    policy: suspend (DCQL, FunkeVerifierAttestations.Companion.AttestationMetadata?) -> Boolean = { _, _ -> true },
): SiopOpenId4Vp {
    val siopOpenId4Vp = SiopOpenId4Vp(siopOpenId4VPConfig, httpClientFactory)

    return object :
        SiopOpenId4Vp,
        AuthorizationRequestResolver,
        Dispatcher by siopOpenId4Vp,
        ErrorDispatcher by siopOpenId4Vp,
        FunkeVerifierAttestations {

        override suspend fun resolveRequestUri(uri: String): Resolution {
            val resolution = siopOpenId4Vp.resolveRequestUri(uri)
            return when (resolution) {
                is Resolution.Invalid -> resolution
                is Resolution.Success -> when (val requestObject = resolution.requestObject) {
                    is ResolvedRequestObject.SiopAuthentication -> resolution
                    is ResolvedRequestObject.OpenId4VPAuthorization -> {
                        val verifierAttestations = requestObject.verifierAttestations
                        val presentationQuery = requestObject.presentationQuery
                        resolution.applyPolicy(presentationQuery, verifierAttestations)
                    }

                    is ResolvedRequestObject.SiopOpenId4VPAuthentication -> {
                        val verifierAttestations = requestObject.verifierAttestations
                        val presentationQuery = requestObject.presentationQuery
                        resolution.applyPolicy(presentationQuery, verifierAttestations)
                    }
                }
            }
        }

        private suspend fun Resolution.Success.applyPolicy(
            presentationQuery: PresentationQuery,
            verifierAttestations: VerifierAttestations?,
        ): Resolution =
            when (presentationQuery) {
                is PresentationQuery.ByPresentationDefinition -> this
                is PresentationQuery.ByDigitalCredentialsQuery -> {
                    if (checkPolicy(presentationQuery.value, verifierAttestations)) this
                    else Resolution.Invalid(InvalidVerifierAttestations("Policy violated"), null)
                }
            }

        private suspend fun checkPolicy(
            dcql: DCQL,
            verifierAttestations: VerifierAttestations?,
        ): Boolean {
            val rpMetadata =
                verifierAttestations?.value?.first()?.let {
                    httpClientFactory().use { httpClient ->
                        it.relyingPartyCertificateMetadata(httpClient)
                    }.getOrThrow()
                }
            return policy(dcql, rpMetadata)
        }
    }
}
