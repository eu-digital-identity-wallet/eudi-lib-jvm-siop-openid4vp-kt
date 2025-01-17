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

import kotlinx.serialization.Serializable

@Serializable
@JvmInline
public value class Format(public val value: String) {
    init {
        require(value.isNotBlank()) { "Format cannot be blank" }
    }

    override fun toString(): String = value

    public companion object {
        public val MsoMdoc: Format get() = Format(OpenId4VPSpec.FORMAT_MSO_MDOC)
        public val SdJwtVcDeprecated: Format get() = Format(OpenId4VPSpec.FORMAT_SD_JWT_VC)
        public val SdJwtVc: Format get() = Format(OpenId4VPSpec.FORMAT_SD_JWT_VC)
        public val W3CLdpVc: Format get() = Format(OpenId4VPSpec.FORMAT_W3C_JSONLD_DATA_INTEGRITY)
        public val W3CJwtVcJsonLd: Format get() = Format(OpenId4VPSpec.FORMAT_W3C_JSONLD_SIGNED_JWT)
        public val W3CJwtVcJson: Format get() = Format(OpenId4VPSpec.FORMAT_W3C_SIGNED_JWT)
    }
}
