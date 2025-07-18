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

import com.nimbusds.jose.JWSAlgorithm

private val FullySpecifiedJwsAlgorithms: Set<JWSAlgorithm> by lazy {
    setOf(
        JWSAlgorithm.HS256,
        JWSAlgorithm.HS384,
        JWSAlgorithm.HS512,
        JWSAlgorithm.RS256,
        JWSAlgorithm.RS384,
        JWSAlgorithm.RS512,
        JWSAlgorithm.ES256,
        JWSAlgorithm.ES256K,
        JWSAlgorithm.ES384,
        JWSAlgorithm.ES512,
        JWSAlgorithm.PS256,
        JWSAlgorithm.PS384,
        JWSAlgorithm.PS512,
        JWSAlgorithm.Ed25519,
        JWSAlgorithm.Ed448,
    )
}

internal val JWSAlgorithm.isFullySpecified: Boolean
    get() = this in FullySpecifiedJwsAlgorithms

internal val JWSAlgorithm.isSignature: Boolean
    get() = this in JWSAlgorithm.Family.SIGNATURE
