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
package eu.europa.ec.eudi.openid4vp.internal

import com.nimbusds.jose.JWEAlgorithm
import com.nimbusds.jose.jwk.Curve
import com.nimbusds.jose.jwk.JWKSet
import com.nimbusds.jose.jwk.KeyUse
import com.nimbusds.jose.jwk.gen.ECKeyGenerator
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator
import eu.europa.ec.eudi.openid4vp.EncryptionRequirement

internal fun EncryptionRequirement.Required.ephemeralJwkSet(): JWKSet {
    val keys = buildList {
        if (supportedEncryptionAlgorithms.any { it in JWEAlgorithm.Family.RSA }) {
            val rsaKey = RSAKeyGenerator(RSAKeyGenerator.MIN_KEY_SIZE_BITS, false)
                .keyID("eph#0")
                .keyUse(KeyUse.ENCRYPTION)
                .generate()
            add(rsaKey)
        }

        if (supportedEncryptionAlgorithms.any { it in JWEAlgorithm.Family.ECDH_ES }) {
            val ecKey = ECKeyGenerator(Curve.P_256)
                .keyID("eph#1")
                .keyUse(KeyUse.ENCRYPTION)
                .generate()
            add(ecKey)
        }
    }

    return JWKSet(keys)
}
