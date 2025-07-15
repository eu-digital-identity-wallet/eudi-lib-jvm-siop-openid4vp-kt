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
import com.nimbusds.jose.JWSAlgorithm.Family.SIGNATURE
import com.nimbusds.jose.JWSAlgorithm.parse
import com.nimbusds.jose.jwk.JWKSet
import com.nimbusds.jose.jwk.KeyUse
import eu.europa.ec.eudi.openid4vp.*
import eu.europa.ec.eudi.openid4vp.RequestValidationError.InvalidClientMetaData
import eu.europa.ec.eudi.openid4vp.RequestValidationError.UnsupportedClientMetaData
import eu.europa.ec.eudi.openid4vp.internal.ensure
import eu.europa.ec.eudi.openid4vp.internal.response.EncrypterFactory
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.*

@Serializable
internal data class UnvalidatedClientMetaData(
    @SerialName(OpenId4VPSpec.JWKS) val jwks: JsonObject? = null,
    @SerialName("subject_syntax_types_supported") val subjectSyntaxTypesSupported: List<String>? = emptyList(),

    @SerialName(OpenId4VPSpec.RESPONSE_ENCRYPTION_METHODS_SUPPORTED)
    val responseEncryptionMethodsSupported: List<String>? = null,

    @SerialName("vp_formats") val vpFormats: VpFormatsTO,
)

@Serializable
internal class VpFormatsTO(
    @SerialName("vc+sd-jwt") val vcSdJwt: VcSdJwtTO? = null,
    @SerialName("mso_mdoc") val msoMdoc: MsoMdocTO? = null,
) {

    fun toDomain(): VpFormats {
        return VpFormats(vcSdJwt?.toDomain(), msoMdoc?.toDomain())
    }

    companion object {

        fun make(fs: VpFormats): VpFormatsTO {
            return VpFormatsTO(
                vcSdJwt = fs.sdJwtVc?.let { VcSdJwtTO.make(it) },
                msoMdoc = fs.msoMdoc?.let { MsoMdocTO.make(it) },
            )
        }
    }
}

@Serializable
internal class VcSdJwtTO(
    @SerialName("sd-jwt_alg_values") val sdJwtAlgorithms: List<String>? = null,
    @SerialName("kb-jwt_alg_values") val kdJwtAlgorithms: List<String>? = null,
) {
    fun toDomain(): VpFormat.SdJwtVc {
        return VpFormat.SdJwtVc(
            sdJwtAlgorithms = sdJwtAlgorithms.algs(),
            kbJwtAlgorithms = kdJwtAlgorithms.algs(),
        )
    }

    companion object {
        fun make(f: VpFormat.SdJwtVc): VcSdJwtTO {
            return VcSdJwtTO(
                sdJwtAlgorithms = f.sdJwtAlgorithms.takeIf { it.isNotEmpty() }?.map { it.name },
                kdJwtAlgorithms = f.kbJwtAlgorithms.takeIf { it.isNotEmpty() }?.map { it.name },
            )
        }
    }
}

@Serializable
internal class MsoMdocTO(
    @SerialName("alg") val alg: List<String>? = null,
) {
    fun toDomain(): VpFormat.MsoMdoc {
        return VpFormat.MsoMdoc(alg.algs())
    }

    companion object {

        fun make(f: VpFormat.MsoMdoc): MsoMdocTO {
            return MsoMdocTO(f.algorithms.map { it.name })
        }
    }
}

internal fun List<String>?.algs() = this?.mapNotNull { parse(it).takeIf { SIGNATURE.contains(it) } }.orEmpty()

internal data class ValidatedClientMetaData(
    val jwkSet: JWKSet? = null,
    val subjectSyntaxTypesSupported: List<SubjectSyntaxType> = emptyList(),
    val responseEncryptionMethodsSupported: List<EncryptionMethod>? = null,
    val vpFormats: VpFormats,
)

@Throws(AuthorizationRequestException::class)
internal fun SiopOpenId4VPConfig.responseEncryptionRequirement(
    metadata: ValidatedClientMetaData,
    responseMode: ResponseMode,
): ResponseEncryptionRequirement? =
    responseEncryptionConfiguration.responseEncryptionRequirement(metadata, responseMode)

/**
 * Method checks whether verifier requested from wallet to reply using an encrypted authorization response, via his [responseMode].
 * If there are such requirements, it makes sure that the wallet can fulfill the requirements provided in [metadata].
 *
 * @param metadata verifier's client metadata
 * @param responseMode verifier requested response mode
 * @receiver the wallet's [ResponseEncryptionConfiguration] which be used to validate verifier's authorization response encryption requirements
 *
 * @return
 * * <code>null</code> means that the verifier requires a plain response.
 * * [ResponseEncryptionRequirement] means that the verifier has requested an encrypted response, and wallet has a
 * suitable option ([ResponseEncryptionConfiguration.Supported]) configured.
 */
@Throws(AuthorizationRequestException::class)
internal fun ResponseEncryptionConfiguration.responseEncryptionRequirement(
    metadata: ValidatedClientMetaData,
    responseMode: ResponseMode,
): ResponseEncryptionRequirement? {
    if (!responseMode.requiresEncryption()) {
        return null
    }

    ensure(null != metadata.jwkSet && null != metadata.responseEncryptionMethodsSupported) {
        InvalidClientMetaData(
            "Verifier's response mode requires encryption, but no encryption parameters have been provided via Client Metadata",
        ).asException()
    }
    ensure(this is ResponseEncryptionConfiguration.Supported) {
        UnsupportedClientMetaData("Wallet doesn't support encrypting authorization responses").asException()
    }

    val encryptionMethod = run {
        val verifierSupportedMethods = metadata.responseEncryptionMethodsSupported.toSet()
        supportedMethods.firstOrNull {
                walletSupportedEncryptionMethod ->
            walletSupportedEncryptionMethod in verifierSupportedMethods
        } ?: throw UnsupportedClientMetaData("Wallet doesn't support any of the encryption methods supported by verifier").asException()
    }

    val (encryptionAlgorithm, encryptionKey) = supportedAlgorithms.firstNotNullOfOrNull { walletSupportedEncryptionAlgorithm ->
        val encryptionKey = metadata.jwkSet.keys.firstOrNull { key ->
            (null == key.keyUse || KeyUse.ENCRYPTION == key.keyUse) &&
                walletSupportedEncryptionAlgorithm.name == key.algorithm?.name &&
                EncrypterFactory.canBeUsed(walletSupportedEncryptionAlgorithm, key)
        }

        if (null != encryptionKey) {
            walletSupportedEncryptionAlgorithm to encryptionKey
        } else {
            null
        }
    } ?: throw UnsupportedClientMetaData("Wallet doesn't support any of the encryption algorithms supported by verifier").asException()

    return ResponseEncryptionRequirement(encryptionAlgorithm, encryptionMethod, encryptionKey)
}
