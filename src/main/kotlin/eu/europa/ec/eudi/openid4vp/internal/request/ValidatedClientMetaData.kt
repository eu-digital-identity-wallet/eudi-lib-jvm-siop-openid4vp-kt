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

@Serializable
internal data class UnvalidatedClientMetaData(
    @SerialName("jwks_uri") val jwksUri: String? = null,
    @SerialName("jwks") val jwks: JsonObject? = null,
    @SerialName("subject_syntax_types_supported") val subjectSyntaxTypesSupported: List<String>? = emptyList(),
    @SerialName("authorization_signed_response_alg") val authorizationSignedResponseAlg: String? = null,
    @SerialName("authorization_encrypted_response_alg") val authorizationEncryptedResponseAlg: String? = null,
    @SerialName("authorization_encrypted_response_enc") val authorizationEncryptedResponseEnc: String? = null,
    @SerialName("vp_formats") val vpFormats: VpFormatsTO? = null,
)

@Serializable
internal class VpFormatsTO(
    @SerialName("vc+sd-jwt") val vcSdJwt: VcSdJwtTO? = null,
    @SerialName("mso_mdoc") val msoMdoc: JsonObject? = null,
) {
    companion object {

        fun make(fs: VpFormats): VpFormatsTO {
            val vcSdJwt = fs.values.filterIsInstance<VpFormat.SdJwtVc>().run {
                check(size <= 1)
                firstOrNull()?.let { VcSdJwtTO.make(it) }
            }
            val msdMdoc = fs.values.filterIsInstance<VpFormat.MsoMdoc>().run {
                check(size <= 1)
                firstOrNull()?.let { JsonObject(emptyMap()) }
            }
            return VpFormatsTO(vcSdJwt, msdMdoc)
        }
    }
}

@Serializable
internal class VcSdJwtTO(
    @SerialName("sd-jwt_alg_values") val sdJwtAlgorithms: List<String>? = null,
    @SerialName("kb-jwt_alg_values") val kdJwtAlgorithms: List<String>? = null,
) {
    companion object {
        fun make(f: VpFormat.SdJwtVc): VcSdJwtTO {
            return VcSdJwtTO(
                sdJwtAlgorithms = f.sdJwtAlgorithms.takeIf { it.isNotEmpty() }?.map { it.name },
                kdJwtAlgorithms = f.kbJwtAlgorithms.takeIf { it.isNotEmpty() }?.map { it.name },
            )
        }
    }
}

internal data class ValidatedClientMetaData(
    val jwkSet: JWKSet? = null,
    val subjectSyntaxTypesSupported: List<SubjectSyntaxType> = emptyList(),
    val authorizationSignedResponseAlg: JWSAlgorithm? = null,
    val authorizationEncryptedResponseAlg: JWEAlgorithm? = null,
    val authorizationEncryptedResponseEnc: EncryptionMethod? = null,
    val vpFormats: VpFormats = VpFormats(emptyList()),
)

@Throws(AuthorizationRequestException::class)
internal fun SiopOpenId4VPConfig.jarmRequirement(metaData: ValidatedClientMetaData): JarmRequirement? =
    jarmConfiguration.jarmRequirement(metaData)

/**
 * Method checks whether verifier requested from wallet to reply using JARM, via his [metaData].
 * If there are such requirements, it makes sure that the wallet can fulfill those requirements.
 *
 * @param metaData verifier's client medata
 * @receiver the wallet's [JarmConfiguration] which be used to validate verifier's JARM requirements
 *
 * @return <em>null</em> value means that the verifier requires a plain response.
 * [JarmRequirement.Signed] means that the verifier has requested a sign response, and wallet has a suitable
 * signer ([JarmConfiguration.Signing] or [JarmConfiguration.SigningAndEncryption]) configured.
 * [JarmRequirement.Encrypted] means that the verifier has requested an encrypted response, and wallet has a
 * suitable option ([JarmConfiguration.Encryption] or [JarmConfiguration.SigningAndEncryption]) configured.
 * [JarmRequirement.SignedAndEncrypted] means that the verifier has requested a signed & encrypted response and
 * wallet has a suitable [JarmConfiguration.SigningAndEncryption] option configured.
 */
@Throws(AuthorizationRequestException::class)
internal fun JarmConfiguration.jarmRequirement(metaData: ValidatedClientMetaData): JarmRequirement? {
    val signed = metaData.authorizationSignedResponseAlg?.let { alg ->
        val signingCfg = signingConfig()
        ensure(signingCfg != null) {
            UnsupportedClientMetaData("Wallet doesn't support signed JARM").asException()
        }
        ensure(alg in signingCfg.signer.supportedJWSAlgorithms()) {
            UnsupportedClientMetaData("Wallet doesn't support $alg ").asException()
        }
        JarmRequirement.Signed(alg)
    }
    val encrypted = metaData.authorizationEncryptedResponseAlg?.let { alg ->
        val encryptionCfg = encryptionConfig()
        ensure(encryptionCfg != null) { UnsupportedClientMetaData("Wallet doesn't support encrypted JARM").asException() }
        ensure(alg in encryptionCfg.supportedAlgorithms) {
            UnsupportedClientMetaData("Wallet doesn't support $alg ").asException()
        }
        metaData.authorizationEncryptedResponseEnc?.let { enc ->
            ensure(enc in encryptionCfg.supportedMethods) {
                UnsupportedClientMetaData("Wallet doesn't support $enc ").asException()
            }
            metaData.jwkSet?.let { set -> JarmRequirement.Encrypted(alg, enc, set) }
        }
    }
    return when {
        signed != null && encrypted != null -> JarmRequirement.SignedAndEncrypted(signed, encrypted)
        signed != null && encrypted == null -> signed
        signed == null && encrypted != null -> encrypted
        else -> null
    }
}
