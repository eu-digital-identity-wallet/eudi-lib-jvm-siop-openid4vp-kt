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
            VpFormats.ensureUniquePerFormat(
                listOf(VpFormat.MsoMdoc, VpFormat.SdJwtVc.ES256),
            )
        }
    }

    @Test
    fun `vp_format with multiple format instances for a given format is not allowed`() {
        assertThrows<IllegalArgumentException> {
            VpFormats.ensureUniquePerFormat(listOf(VpFormat.MsoMdoc, VpFormat.MsoMdoc))
            VpFormats.ensureUniquePerFormat(
                listOf(
                    VpFormat.SdJwtVc.ES256,
                    VpFormat.sdJwtVc(
                        sdJwtAlgorithms = listOf(JWSAlgorithm.RS256),
                        kbJwtAlgorithms = listOf(JWSAlgorithm.RS256),
                    ),
                ),
            )
        }
    }
}
