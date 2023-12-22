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

import com.nimbusds.jose.EncryptionMethod
import com.nimbusds.jose.JWEAlgorithm
import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.jwk.JWKSet
import eu.europa.ec.eudi.openid4vp.*
import eu.europa.ec.eudi.openid4vp.RequestValidationError.UnsupportedClientMetaData
import eu.europa.ec.eudi.openid4vp.internal.ensure
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.JsonObject
import java.net.URL

@Serializable
internal data class UnvalidatedClientMetaData(
    @SerialName("jwks_uri") val jwksUri: String? = null,
    @SerialName("jwks") val jwks: JsonObject? = null,
    @SerialName("subject_syntax_types_supported") val subjectSyntaxTypesSupported: List<String>? = emptyList(),
    @SerialName("authorization_signed_response_alg") val authorizationSignedResponseAlg: String? = null,
    @SerialName("authorization_encrypted_response_alg") val authorizationEncryptedResponseAlg: String? = null,
    @SerialName("authorization_encrypted_response_enc") val authorizationEncryptedResponseEnc: String? = null,
)

internal sealed interface ClientMetaDataSource {
    data class ByValue(val metaData: UnvalidatedClientMetaData) : ClientMetaDataSource
    data class ByReference(val url: URL) : ClientMetaDataSource
}

internal data class ValidatedClientMetaData(
    val jwkSet: JWKSet? = null,
    val subjectSyntaxTypesSupported: List<SubjectSyntaxType> = emptyList(),
    val authorizationSignedResponseAlg: JWSAlgorithm? = null,
    val authorizationEncryptedResponseAlg: JWEAlgorithm? = null,
    val authorizationEncryptedResponseEnc: EncryptionMethod? = null,
)

@Throws(AuthorizationRequestException::class)
internal fun ValidatedClientMetaData.jarmOption(cfg: SiopOpenId4VPConfig): JarmOption? {
    val jarmConfig = cfg.jarmConfiguration
    val signedResponse = authorizationSignedResponseAlg?.let { alg ->
        ensure(alg in jarmConfig.supportedSigningAlgorithms()) {
            UnsupportedClientMetaData("Wallet doesn't support $alg ").asException()
        }
        JarmOption.SignedResponse(alg)
    }
    val encryptedResponse = authorizationEncryptedResponseAlg?.let { alg ->
        ensure(alg in jarmConfig.supportedEncryptionAlgorithms()) {
            UnsupportedClientMetaData("Wallet doesn't support $alg ").asException()
        }
        authorizationEncryptedResponseEnc?.let { enc ->
            ensure(enc in jarmConfig.supportedEncryptionMethods()) {
                UnsupportedClientMetaData("Wallet doesn't support $enc ").asException()
            }
            jwkSet?.let { set -> JarmOption.EncryptedResponse(alg, enc, set) }
        }
    }

    fun requiredSignedResponse() = checkNotNull(signedResponse)
    fun requiredEncryptedResponse() = checkNotNull(encryptedResponse)

    return when ((signedResponse != null) to (encryptedResponse != null)) {
        true to true -> JarmOption.SignedAndEncryptedResponse(requiredSignedResponse(), requiredEncryptedResponse())
        true to false -> requiredSignedResponse()
        false to true -> requiredEncryptedResponse()
        else -> null
    }
}
