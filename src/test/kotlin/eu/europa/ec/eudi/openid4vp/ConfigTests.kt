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

import com.nimbusds.jose.JWSAlgorithm
import org.junit.jupiter.api.assertDoesNotThrow
import org.junit.jupiter.api.assertThrows
import kotlin.test.Test

class ConfigTests {

    @Test
    fun `vp_format with at most one instance per format is ok`() {
        assertDoesNotThrow {
            VpFormats(VpFormat.MsoMdoc.ES256, VpFormat.SdJwtVc.ES256)
        }
    }

    @Test
    fun `vp_format with multiple format instances for a given format is not allowed`() {
        assertThrows<IllegalArgumentException> {
            VpFormats(
                VpFormat.MsoMdoc(listOf(JWSAlgorithm.ES384)),
                VpFormat.MsoMdoc(listOf(JWSAlgorithm.ES384)),
            )
        }

        assertThrows<IllegalArgumentException> {
            VpFormats(
                VpFormat.SdJwtVc(
                    sdJwtAlgorithms = listOf(JWSAlgorithm.ES384),
                    kbJwtAlgorithms = listOf(JWSAlgorithm.ES256),
                ),
                VpFormat.SdJwtVc(
                    sdJwtAlgorithms = listOf(JWSAlgorithm.RS256),
                    kbJwtAlgorithms = listOf(JWSAlgorithm.RS256),
                ),
            )
        }
    }
}
