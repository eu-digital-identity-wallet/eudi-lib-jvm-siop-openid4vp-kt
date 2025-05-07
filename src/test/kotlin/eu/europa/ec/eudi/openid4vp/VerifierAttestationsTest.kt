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

import com.nimbusds.jwt.SignedJWT
import eu.europa.ec.eudi.openid4vp.dcql.ClaimPath
import eu.europa.ec.eudi.openid4vp.dcql.CredentialSets
import eu.europa.ec.eudi.openid4vp.dcql.Credentials
import eu.europa.ec.eudi.openid4vp.internal.jsonSupport
import eu.europa.ec.eudi.openid4vp.internal.request.requestObject
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.test.runTest
import kotlinx.coroutines.withContext
import kotlinx.serialization.Required
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.jsonPrimitive
import org.junit.jupiter.api.Test
import kotlin.test.assertNotNull

class VerifierAttestationsTest {
    val jar = """
        eyJ0eXAiOiJvYXV0aC1hdXRoei1yZXErand0IiwiYWxnIjoiRVMyNTYiLCJ4NWMiOlsiTUlJQjdEQ0NBWk9nQXdJQkFnSVVIajhxc0JpSFVadm5FcEdlcDk3OE5ZUU5qcE13Q2dZSUtvWkl6ajBFQXdJd0d6RVpNQmNHQTFVRUF3d1FSMlZ5YldGdUlGSmxaMmx6ZEhKaGNqQWVGdzB5TlRBME1URXhOelV5TXpOYUZ3MHlOakEwTVRFeE56VXlNek5hTUJJeEVEQU9CZ05WQkFNTUIwUmxiVzhnVWxBd1dUQVRCZ2NxaGtqT1BRSUJCZ2dxaGtqT1BRTUJCd05DQUFRVUpQR2hhYVQ4SmErdHBuVlVqVXdoWlZxM0xEVjc1RWNCWEdMcGFXL2c0Z2h4ZkRUUVpSTS8zVEQyZ0dWTm5KTjZtNy8vMEZaZzlsemxLVmJtSXMxR280RzlNSUc2TUFrR0ExVWRFd1FDTUFBd0N3WURWUjBQQkFRREFnV2dNQk1HQTFVZEpRUU1NQW9HQ0NzR0FRVUZCd01CTUJvR0ExVWRFUVFUTUJHQ0QyWjFibXRsTFhkaGJHeGxkQzVrWlRBdkJnTlZIUjhFS0RBbU1DU2dJcUFnaGg1b2RIUndjem92TDJaMWJtdGxMWGRoYkd4bGRDNWtaUzlqWVM5amNtd3dIUVlEVlIwT0JCWUVGSzRZS0VSa1pYUCt0RzllRFJhVmRFQko2aDIyTUI4R0ExVWRJd1FZTUJhQUZNeG5LTGtHaWZiVEtyeGJHWGNGWEs2UkZRZDNNQW9HQ0NxR1NNNDlCQU1DQTBjQU1FUUNJUUQrWVhmaWkwdHprZEZ4M2lZYTdpc2F2YjFzVmgzaWNDU2IrQkJ4UkxKdTdnSWZUdDIzRGtoZkNhLzVvZ0FUR3c1YXhtWGFPTjFKUFI4OVA2OFVNUFBXTnc9PSJdfQ.eyJyZXNwb25zZV90eXBlIjoidnBfdG9rZW4iLCJjbGllbnRfaWQiOiJ4NTA5X3Nhbl9kbnM6ZnVua2Utd2FsbGV0LmRlIiwicmVzcG9uc2VfdXJpIjoiaHR0cHM6Ly9mdW5rZS13YWxsZXQuZGUvb2lkNHZwL3Jlc3BvbnNlIiwicmVzcG9uc2VfbW9kZSI6ImRpcmVjdF9wb3N0Lmp3dCIsIm5vbmNlIjoiODYwMzAzNDA3NTI4MzI0NTI2ODcxMzEzIiwiZGNxbF9xdWVyeSI6eyJjcmVkZW50aWFscyI6W3siaWQiOiJwaWQiLCJmb3JtYXQiOiJkYytzZC1qd3QiLCJtZXRhIjp7InZjdF92YWx1ZXMiOlsiaHR0cHM6Ly9kZW1vLnBpZC1pc3N1ZXIuYnVuZGVzZHJ1Y2tlcmVpLmRlL2NyZWRlbnRpYWxzL3BpZC8xLjAiLCJ1cm46ZXUuZXVyb3BhLmVjLmV1ZGk6cGlkOjEiXX0sImNsYWltcyI6W3sicGF0aCI6WyJmYW1pbHlfbmFtZSJdfSx7InBhdGgiOlsiZ2l2ZW5fbmFtZSJdfV19XX0sImNsaWVudF9tZXRhZGF0YSI6eyJqd2tzIjp7ImtleXMiOlt7Imt0eSI6IkVDIiwiY3J2IjoiUC0yNTYiLCJ4IjoiemtUTGZhXzU2cU5qa3c4aUZRbEV0XzRxMWdSSmk1Skl3dVVzREg3NEwxQSIsInkiOiItS21aNmFCR24tVXllck9PaHNnODEwNjFKOUlJdnNaNmR6dTdBWTNnc1djIiwia2lkIjoiekRuYWV3WVVGQWtVTDZIYTVRMUg5eG84a01zR0c4Y0dOWTNhWDlHN3BrdUtpMVdUOSIsInVzZSI6ImVuYyJ9XX0sInZwX2Zvcm1hdHMiOnsibXNvX21kb2MiOnsiYWxnIjpbIkVkRFNBIiwiRVMyNTYiLCJFUzM4NCJdfSwidmMrc2Qtand0Ijp7ImtiLWp3dF9hbGdfdmFsdWVzIjpbIkVkRFNBIiwiRVMyNTYiLCJFUzM4NCIsIkVTMjU2SyJdLCJzZC1qd3RfYWxnX3ZhbHVlcyI6WyJFZERTQSIsIkVTMjU2IiwiRVMzODQiLCJFUzI1NksiXX0sImRjK3NkLWp3dCI6eyJrYi1qd3RfYWxnX3ZhbHVlcyI6WyJFZERTQSIsIkVTMjU2IiwiRVMzODQiLCJFUzI1NksiXSwic2Qtand0X2FsZ192YWx1ZXMiOlsiRWREU0EiLCJFUzI1NiIsIkVTMzg0IiwiRVMyNTZLIl19fSwiYXV0aG9yaXphdGlvbl9lbmNyeXB0ZWRfcmVzcG9uc2VfYWxnIjoiRUNESC1FUyIsImF1dGhvcml6YXRpb25fZW5jcnlwdGVkX3Jlc3BvbnNlX2VuYyI6IkEyNTZHQ00iLCJjbGllbnRfbmFtZSI6Ikdlcm1hbiBSZWdpc3RyYXIiLCJyZXNwb25zZV90eXBlc19zdXBwb3J0ZWQiOlsidnBfdG9rZW4iXX0sInN0YXRlIjoiNzY0MTQzNTE2OTMzMzIwNTQwNzQ0NTg0IiwiYXVkIjoiaHR0cHM6Ly9mdW5rZS13YWxsZXQuZGUiLCJleHAiOjE3NDY1Mzg0ODQsImlhdCI6MTc0NjUzODE4NCwidmVyaWZpZXJfYXR0ZXN0YXRpb25zIjpbeyJmb3JtYXQiOiJqd3QiLCJkYXRhIjoiZXlKMGVYQWlPaUp5WXkxeWNDdHFkM1FpTENKNE5XTWlPbHNpVFVsSlFtUlVRME5CVW5WblFYZEpRa0ZuU1ZWSWMxTnRZa2QxVjBGV1dsWllhbkZ2YVdSeFFWWkRiRWQ0TkZsM1EyZFpTVXR2V2tsNmFqQkZRWGRKZDBkNlJWcE5RbU5IUVRGVlJVRjNkMUZTTWxaNVlsZEdkVWxHU214YU1teDZaRWhLYUdOcVFXVkdkekI1VGxSQmVrMTZRWGhQVkZVMFRsUkdZVVozTUhsT2FrRjZUWHBCZUU5VVZUUk9WRVpoVFVKemVFZFVRVmhDWjA1V1FrRk5UVVZGWkd4amJURm9ZbWxDVTFwWFpIQmpNMUo1V1ZoSmQxZFVRVlJDWjJOeGFHdHFUMUJSU1VKQ1oyZHhhR3RxVDFCUlRVSkNkMDVEUVVGVFVWZERSVk5HWkRCWmQyMDVjMHM0TjFoNGNYaEVVRFIzVDBGaFpFVkxaMk5hUmxaWU4yNXdaVE5CVEVaclltcHpXRmxhU25OVVIyaFdjREFyUWpWYWRGVmhiekpPYzNsNlNrTkxlbTVRZDFSNk1uZEtZMjk2TUhkUGVrRmhRbWRPVmtoU1JVVkZla0ZTWjJjNWJXUlhOWEphVXpFeldWZDRjMXBZVVhWYVIxVjNTRkZaUkZaU01FOUNRbGxGUmsxNGJrdE1hMGRwWm1KVVMzSjRZa2RZWTBaWVN6WlNSbEZrTTAxQmIwZERRM0ZIVTAwME9VSkJUVU5CTUdkQlRVVlZRMGxSUkRSU2FVeEtaWFZXUkhKRlNGTjJhMUJwVUdaQ2RrMTRRVmhTUXpaUWRVVjRiM0JWUjBOR1pHWk9URkZKWjBoSFUyRTFkVFZhY1ZWMFEzSnVUV2xoUldGblpVODNNWEpxZWtKc2IzWXdXVlZJTkNzMlJVeHBiMWs5SWwwc0ltRnNaeUk2SWtWVE1qVTJJbjAuZXlKd2NtbDJZV041WDNCdmJHbGplU0k2SW1oMGRIQnpPaTh2WlhoaGJYQnNaUzVqYjIwdmNISnBkbUZqZVMxd2IyeHBZM2tpTENKd2RYSndiM05sSWpwYmV5SnNiMk5oYkdVaU9pSmxiaTFWVXlJc0ltNWhiV1VpT2lKVWJ5QnlaV2RwYzNSbGNpQmhJRzVsZHlCMWMyVnlJbjFkTENKamIyNTBZV04wSWpwN0luZGxZbk5wZEdVaU9pSm9kSFJ3Y3pvdkwyVjRZVzF3YkdVdVkyOXRMMk52Ym5SaFkzUWlMQ0psTFcxaGFXd2lPaUpqYjI1MFlXTjBRR1Y0WVcxd2JHVXVZMjl0SWl3aWNHaHZibVVpT2lJck1USXpORFUyTnpnNU1DSjlMQ0pqY21Wa1pXNTBhV0ZzY3lJNlczc2lhV1FpT2lKd2FXUWlMQ0ptYjNKdFlYUWlPaUprWXl0elpDMXFkM1FpTENKdFpYUmhJanA3SW5aamRGOTJZV3gxWlhNaU9sc2lhSFIwY0hNNkx5OWtaVzF2TG5CcFpDMXBjM04xWlhJdVluVnVaR1Z6WkhKMVkydGxjbVZwTG1SbEwyTnlaV1JsYm5ScFlXeHpMM0JwWkM4eExqQWlMQ0oxY200NlpYVXVaWFZ5YjNCaExtVmpMbVYxWkdrNmNHbGtPakVpWFgwc0ltTnNZV2x0Y3lJNlczc2ljR0YwYUNJNld5Sm1ZVzFwYkhsZmJtRnRaU0pkZlN4N0luQmhkR2dpT2xzaVoybDJaVzVmYm1GdFpTSmRmVjE5WFN3aVkzSmxaR1Z1ZEdsaGJGOXpaWFJ6SWpwYmV5SnZjSFJwYjI1eklqcGJXeUp3YVdRaVhWMHNJbkpsY1hWcGNtVmtJanAwY25WbExDSndkWEp3YjNObElqcGJleUpzYjJOaGJHVWlPaUpsYmkxVlV5SXNJbTVoYldVaU9pSlVieUJ5WldkcGMzUmxjaUJoSUc1bGR5QjFjMlZ5SW4xZGZWMHNJbk4xWWlJNklrTk9QVVJsYlc4Z1VsQWlMQ0pxZEdraU9pSTBNakZoTWpnek9TMWtOak14TFRReU1ETXRPVEJrTXkxbE4yWTJaREpsWVdGbU9EUWlMQ0p6ZEdGMGRYTWlPbnNpYzNSaGRIVnpYMnhwYzNRaU9uc2lhV1I0SWpvME9EQXdMQ0oxY21raU9pSm9kSFJ3Y3pvdkwyWjFibXRsTFhkaGJHeGxkQzVrWlM5emRHRjBkWE10YldGdVlXZGxiV1Z1ZEM5emRHRjBkWE10YkdsemRDSjlmU3dpY0hWaWJHbGpYMkp2WkhraU9tWmhiSE5sTENKbGJuUnBkR3hsYldWdWRITWlPbHRkTENKelpYSjJhV05sY3lJNlcxMTkucjNURHpNR2JyelVLX0xyTld1XzFJNGYwY0VMZFRoWnZSSE5IQl9ROGVQTWhiRlB4TlE3akdBcktJWDRfTzUyOUQxWDJoVWV1dVNneVc2MVNWTkwwakEifV19.0jJsucCHdX4g24KPVrE3Etu8l4jwWvNda1RfHQNtSBpvjECG_DdkqmjLjtNq0HsNk2enMK-BxDSj9Ev5t2P1Pg
    """.trimIndent()

    @Test
    fun testParsing() = runTest {
        val unvalidatedRequestObject = SignedJWT.parse(jar).requestObject().also { println(it) }
        val attestations = run {
            val verifierAttestationsArray = assertNotNull(unvalidatedRequestObject.verifierAttestations)
            VerifierAttestations.fromJson(verifierAttestationsArray).getOrThrow()
        }
        val funkeAttestations = FunkeVerifierAttestations.parse(attestations).getOrThrow()
    }
}

object FunkeVerifierAttestations {

    suspend fun parse(attestations: VerifierAttestations): Result<List<VerifierAttestationPayload>> =
        coroutineScope {
            runCatching {
                attestations.value
                    .filter { attestations -> attestations.format == "jwt" }
                    .map { attestation ->
                        val jwt = attestation.data.jsonPrimitive.content
                        jwtAttestation(jwt).getOrThrow()
                    }
            }
        }

    suspend fun jwtAttestation(jwt: String): Result<VerifierAttestationPayload> =
        withContext(Dispatchers.IO) {
            runCatching {
                val signedJWT = SignedJWT.parse(jwt)
                jsonSupport.decodeFromString<VerifierAttestationPayload>(signedJWT.jwtClaimsSet.toString())
            }
        }

    @Serializable
    data class VerifierAttestationPayload(
        val sub: String,
        val jti: String,
        val status: StatusWrapper,
        @SerialName("privacy_policy") val privacyPolicy: String,
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
        @SerialName("e-mail") val email: String, // TODO rename attribute
        @SerialName("phone") val phone: String,
    )

    @Serializable
    data class StatusWrapper(
        @SerialName("status_list") val statusList: StatusList,
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
        val credentials: List<Credential>,
        val credentialSet: List<CredentialSet>,
    )

    @Serializable
    data class Credential(
        val id: String,
        val format: String,
        val meta: CredentialMeta,
        val claims: List<ClaimPath>,
    )

    @Serializable
    data class CredentialMeta(
        val vct_values: List<String>,
    )

    @Serializable
    data class CredentialSet(
        val options: List<List<String>>,
        val required: Boolean,
        val purpose: List<LocalizedText>,
    )
}
