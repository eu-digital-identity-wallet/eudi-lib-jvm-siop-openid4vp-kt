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

import com.nimbusds.jose.JWSAlgorithm
import eu.europa.ec.eudi.openid4vp.*
import kotlinx.serialization.Required
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.JsonObject

@Serializable
internal data class UnvalidatedClientMetaData(
    @SerialName(OpenId4VPSpec.JWKS) val jwks: JsonObject? = null,
    @SerialName("subject_syntax_types_supported") val subjectSyntaxTypesSupported: List<String>? = emptyList(),

    @SerialName(OpenId4VPSpec.RESPONSE_ENCRYPTION_METHODS_SUPPORTED)
    val responseEncryptionMethodsSupported: List<String>? = null,

    @SerialName(OpenId4VPSpec.VP_FORMATS_SUPPORTED) @Required val vpFormatsSupported: SupportedVpFormatsTO,
)

@Serializable
internal class SupportedVpFormatsTO(
    @SerialName(OpenId4VPSpec.FORMAT_SD_JWT_VC) val sdJwtVc: SdVcJwtTO? = null,
    @SerialName(OpenId4VPSpec.FORMAT_MSO_MDOC) val msoMdoc: MsoMdocTO? = null,
) {
    fun toDomain(): RequestedVpFormats =
        RequestedVpFormats(
            sdJwtVc = sdJwtVc?.toDomain(),
            msoMdoc = msoMdoc?.toDomain(),
        )

    companion object {
        fun make(fs: SupportedVpFormats): SupportedVpFormatsTO {
            return SupportedVpFormatsTO(
                sdJwtVc = fs.sdJwtVc?.let { SdVcJwtTO.make(it) },
                msoMdoc = fs.msoMdoc?.let { MsoMdocTO.make(it) },
            )
        }
    }
}

@Serializable
internal class SdVcJwtTO(
    @SerialName(OpenId4VPSpec.SD_JWT_VC_SD_JWT_ALGORITHMS) val sdJwtAlgorithms: List<String>? = null,
    @SerialName(OpenId4VPSpec.SD_JWT_VC_KB_JWT_ALGORITHMS) val kdJwtAlgorithms: List<String>? = null,
) {
    fun toDomain(): RequestedVpFormat.SdJwtVc =
        RequestedVpFormat.SdJwtVc(
            sdJwtAlgorithms = sdJwtAlgorithms?.map { JWSAlgorithm.parse(it) }?.toSet(),
            kbJwtAlgorithms = kdJwtAlgorithms?.map { JWSAlgorithm.parse(it) }?.toSet(),
        )

    companion object {
        fun make(f: SupportedVpFormat.SdJwtVc): SdVcJwtTO {
            return SdVcJwtTO(
                sdJwtAlgorithms = f.sdJwtAlgorithms.map { it.name },
                kdJwtAlgorithms = f.kbJwtAlgorithms.map { it.name },
            )
        }
    }
}

@Serializable
internal class MsoMdocTO(
    @SerialName(OpenId4VPSpec.MSO_MDOC_ISSUERAUTH_ALGORITHMS) val issuerAuthAlgorithms: List<Int>? = null,
    @SerialName(OpenId4VPSpec.MSO_MDOC_DEVICEAUTH_ALGORITHMS) val deviceAuthAlgorithms: List<Int>? = null,
) {
    fun toDomain(): RequestedVpFormat.MsoMdoc =
        RequestedVpFormat.MsoMdoc(
            issuerAuthAlgorithms = issuerAuthAlgorithms?.map { CoseAlgorithm(it) }?.toSet(),
            deviceAuthAlgorithms = deviceAuthAlgorithms?.map { CoseAlgorithm(it) }?.toSet(),
        )

    companion object {
        fun make(f: SupportedVpFormat.MsoMdoc): MsoMdocTO {
            return MsoMdocTO(
                issuerAuthAlgorithms = f.issuerAuthAlgorithms.map { it.value },
                deviceAuthAlgorithms = f.deviceAuthAlgorithms.map { it.value },
            )
        }
    }
}

internal data class ValidatedClientMetaData(
    val responseEncryptionSpecification: ResponseEncryptionSpecification? = null,
    val subjectSyntaxTypesSupported: List<SubjectSyntaxType> = emptyList(),
    val vpFormats: RequestedVpFormats,
)
