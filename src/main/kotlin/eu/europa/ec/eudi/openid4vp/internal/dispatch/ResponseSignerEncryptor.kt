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
import eu.europa.ec.eudi.openid4vp.JarmSpec
import java.util.*

internal object ResponseSignerEncryptor {

    fun signEncryptResponse(spec: JarmSpec, data: AuthorizationResponsePayload): String {
        return when (spec) {
            is JarmSpec.SignedResponse -> sign(spec, data).serialize()
            is JarmSpec.EncryptedResponse -> encrypt(spec, data).serialize()
            is JarmSpec.SignedAndEncryptedResponse -> signAndEncrypt(spec, data).serialize()
        }
    }

    private fun sign(
        spec: JarmSpec.SignedResponse,
        data: AuthorizationResponsePayload,
    ): SignedJWT {
        val (holderId, signingAlg, signingKeySet) = spec
        val (signingKey, jwsSigner) = keyAndSigner(signingAlg, signingKeySet)
        val header = JWSHeader.Builder(signingAlg)
            .keyID(signingKey.keyID)
            .build()
        val dataAsJWT = DirectPostForm.of(data).asJWT(holderId)
        return SignedJWT(header, dataAsJWT).apply { sign(jwsSigner) }
    }

    private fun encrypt(
        spec: JarmSpec.EncryptedResponse,
        data: AuthorizationResponsePayload,
    ): EncryptedJWT {
        val (_, jweEncrypter) = keyAndEncryptor(spec.responseEncryptionAlg, spec.encryptionKeySet)
        val jweHeader = JWEHeader(spec.responseEncryptionAlg, spec.responseEncryptionEnc)
        val dataAsJWT = DirectPostForm.of(data).asJWT(spec.holderId)
        return EncryptedJWT(jweHeader, dataAsJWT).apply { encrypt(jweEncrypter) }
    }

    private fun signAndEncrypt(
        spec: JarmSpec.SignedAndEncryptedResponse,
        data: AuthorizationResponsePayload,
    ): JWEObject {
        val signedJwt = sign(spec.signedResponse(), data)
        val (_, jweEncrypter) = keyAndEncryptor(spec.responseEncryptionAlg, spec.encryptionKeySet)
        return JWEObject(
            JWEHeader(spec.responseEncryptionAlg, spec.responseEncryptionEnc),
            Payload(signedJwt),
        ).apply { encrypt(jweEncrypter) }
    }

    private fun JarmSpec.SignedAndEncryptedResponse.signedResponse(): JarmSpec.SignedResponse =
        JarmSpec.SignedResponse(holderId, responseSigningAlg, signingKeySet)

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
