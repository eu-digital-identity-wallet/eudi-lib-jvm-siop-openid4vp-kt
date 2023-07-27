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
package eu.europa.ec.eudi.openid4vp.internal.dispatch

import com.nimbusds.jose.*
import com.nimbusds.jose.JWEAlgorithm.Family
import com.nimbusds.jose.crypto.ECDHEncrypter
import com.nimbusds.jose.crypto.RSAEncrypter
import com.nimbusds.jose.crypto.factories.DefaultJWSSignerFactory
import com.nimbusds.jose.jwk.ECKey
import com.nimbusds.jose.jwk.JWK
import com.nimbusds.jose.jwk.JWKSet
import com.nimbusds.jose.jwk.RSAKey
import com.nimbusds.jwt.EncryptedJWT
import com.nimbusds.jwt.JWTClaimsSet
import com.nimbusds.jwt.SignedJWT
import eu.europa.ec.eudi.openid4vp.AuthorizationResponsePayload
import eu.europa.ec.eudi.openid4vp.JarmOption
import eu.europa.ec.eudi.openid4vp.JarmSpec
import java.util.*

internal object ResponseSignerEncryptor {

    fun signEncryptResponse(spec: JarmSpec, data: AuthorizationResponsePayload): String =
        when (val jarmOption = spec.jarmOption) {
            is JarmOption.SignedResponse -> sign(spec.holderId, jarmOption, data).serialize()
            is JarmOption.EncryptedResponse -> encrypt(spec.holderId, jarmOption, data).serialize()
            is JarmOption.SignedAndEncryptedResponse -> signAndEncrypt(spec.holderId, jarmOption, data).serialize()
        }

    private fun sign(
        holderId: String,
        option: JarmOption.SignedResponse,
        data: AuthorizationResponsePayload,
    ): SignedJWT {
        val (signingAlg, signingKeySet) = option
        val (signingKey, jwsSigner) = keyAndSigner(signingAlg, signingKeySet)
        val header = JWSHeader.Builder(signingAlg)
            .keyID(signingKey.keyID)
            .build()
        val dataAsJWT = DirectPostForm.of(data).asJWT(holderId)
        return SignedJWT(header, dataAsJWT).apply { sign(jwsSigner) }
    }

    private fun encrypt(
        holderId: String,
        option: JarmOption.EncryptedResponse,
        data: AuthorizationResponsePayload,
    ): EncryptedJWT {
        val (jweAlgorithm, encryptionMethod, encryptionKeySet) = option
        val (_, jweEncrypter) = keyAndEncryptor(jweAlgorithm, encryptionKeySet)
        val jweHeader = JWEHeader(jweAlgorithm, encryptionMethod)
        val dataAsJWT = DirectPostForm.of(data).asJWT(holderId)
        return EncryptedJWT(jweHeader, dataAsJWT).apply { encrypt(jweEncrypter) }
    }

    private fun signAndEncrypt(
        holderId: String,
        option: JarmOption.SignedAndEncryptedResponse,
        data: AuthorizationResponsePayload,
    ): JWEObject {
        val signedJwt = sign(holderId, option.signedResponse, data)
        val (jweAlgorithm, encryptionMethod, encryptionKeySet) = option.encryptResponse
        val (_, jweEncrypter) = keyAndEncryptor(jweAlgorithm, encryptionKeySet)
        return JWEObject(
            JWEHeader(jweAlgorithm, encryptionMethod),
            Payload(signedJwt),
        ).apply { encrypt(jweEncrypter) }
    }

    private fun keyAndSigner(
        jwsAlgorithm: JWSAlgorithm,
        keySet: JWKSet,
    ): Pair<JWK, JWSSigner> {
        val signerFactory = DefaultJWSSignerFactory()
        fun signer(key: JWK) = runCatching { signerFactory.createJWSSigner(key, jwsAlgorithm) }.getOrNull()
        return keySet.keys.firstNotNullOfOrNull { key ->
            signer(key)?.let { signer -> key to signer }
        } ?: error("Cannot find appropriate signing key for ${jwsAlgorithm.name}")
    }

    private fun keyAndEncryptor(
        jweAlgorithm: JWEAlgorithm,
        jwkSet: JWKSet,
    ): Pair<JWK, JWEEncrypter> =
        EncrypterFactory
            .findEncrypters(jweAlgorithm, jwkSet)
            .entries
            .firstOrNull()
            ?.toPair()
            ?: error("Cannot find appropriate encryption key for ${jweAlgorithm.name}")

    private fun Map<String, String>.asJWT(holderId: String): JWTClaimsSet {
        return with(JWTClaimsSet.Builder()) {
            issuer(holderId)
            issueTime(Date())
            this@asJWT.entries.map { claim(it.key, it.value) }
            build()
        }
    }
}

private object EncrypterFactory {

    fun findEncrypters(
        algorithm: JWEAlgorithm,
        keySet: JWKSet,
    ): Map<JWK, JWEEncrypter> {
        fun encrypter(key: JWK) = runCatching {
            createEncrypter(key, algorithm)
        }.getOrNull()

        return keySet.keys.mapNotNull { key ->
            encrypter(key)?.let { encrypter -> key to encrypter }
        }.toMap()
    }

    fun createEncrypter(
        key: JWK,
        algorithm: JWEAlgorithm,
    ): JWEEncrypter? =
        familyOf(algorithm)?.let { family ->
            when {
                family == Family.ECDH_ES && key is ECKey -> ECDHEncrypter(key)
                family == Family.RSA && key is RSAKey -> RSAEncrypter(key)
                else -> null
            }
        }

    private val SupportedFamilies = listOf(Family.ECDH_ES, Family.RSA)
    private fun familyOf(algorithm: JWEAlgorithm): Family? =
        SupportedFamilies.firstOrNull { family -> family.contains(algorithm) }
}
