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

import com.nimbusds.jose.JWSObject
import com.nimbusds.jwt.SignedJWT
import eu.europa.ec.eudi.openid4vp.OpenId4VPSpec
import eu.europa.ec.eudi.openid4vp.internal.JwsJson
import eu.europa.ec.eudi.openid4vp.internal.JwsJson.Companion.flatten
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.JsonObject

/**
 * The data of an OpenID4VP authorization request or SIOP Authentication request
 * or a combined OpenId4VP & SIOP request
 * without any validation and regardless of the way they sent to the wallet
 */
@Serializable
internal data class UnvalidatedRequestObject(
    @SerialName("client_metadata") val clientMetaData: JsonObject? = null,
    @SerialName(OpenId4VPSpec.NONCE) val nonce: String? = null,
    @SerialName("client_id") val clientId: String? = null,
    @SerialName("response_type") val responseType: String? = null,
    @SerialName("response_mode") val responseMode: String? = null,
    @SerialName(OpenId4VPSpec.RESPONSE_URI) val responseUri: String? = null,
    @SerialName(OpenId4VPSpec.DCQL_QUERY) val dcqlQuery: JsonObject? = null,
    @SerialName("redirect_uri") val redirectUri: String? = null,
    @SerialName("scope") val scope: String? = null,
    @SerialName("state") val state: String? = null,
    @SerialName("id_token_type") val idTokenType: String? = null,
    @SerialName(OpenId4VPSpec.TRANSACTION_DATA) val transactionData: TransactionDataTO? = null,
    @SerialName(OpenId4VPSpec.VERIFIER_INFO) val verifierInfo: VerifierInfoTO? = null,
    @SerialName(OpenId4VPSpec.EXPECTED_ORIGINS) val expectedOrigins: List<String>? = null,
)

internal sealed interface ReceivedRequest {
    data class Unsigned(val requestObject: UnvalidatedRequestObject) : ReceivedRequest
    data class Signed(val jwsJson: JwsJson) : ReceivedRequest {
        companion object {
            operator fun invoke(signedJwt: SignedJWT): Signed = Signed(JwsJson.from(signedJwt).getOrThrow())
        }
    }

    companion object
}

/**
 * Decomposes a Nimbus [SignedJWT] into [JwsJson].
 */
private fun JwsJson.Companion.from(signedJwt: SignedJWT): Result<JwsJson> = runCatching {
    require(signedJwt.state == JWSObject.State.SIGNED) { "JWS is not signed" }
    JwsJson.from(signedJwt.serialize()).getOrThrow()
}

internal fun ReceivedRequest.Signed.toSignedJwts(): List<SignedJWT> =
    jwsJson.flatten().map {
        SignedJWT.parse("${it.protected}.${it.payload}.${it.signature}")
    }
