/*
 *
 *  * Copyright (c) 2023 European Commission
 *  *
 *  * Licensed under the Apache License, Version 2.0 (the "License");
 *  * you may not use this file except in compliance with the License.
 *  * You may obtain a copy of the License at
 *  *
 *  *     http://www.apache.org/licenses/LICENSE-2.0
 *  *
 *  * Unless required by applicable law or agreed to in writing, software
 *  * distributed under the License is distributed on an "AS IS" BASIS,
 *  * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  * See the License for the specific language governing permissions and
 *  * limitations under the License.
 *
 */

package eu.europa.ec.eudi.openid4vp.internal.dispatch

import com.nimbusds.jose.*
import com.nimbusds.jose.crypto.ECDHEncrypter
import com.nimbusds.jose.crypto.RSAEncrypter
import com.nimbusds.jose.jwk.ECKey
import com.nimbusds.jose.jwk.JWKSet
import com.nimbusds.jose.jwk.KeyType
import com.nimbusds.jose.jwk.RSAKey
import com.nimbusds.jwt.EncryptedJWT
import com.nimbusds.jwt.JWTClaimsSet
import eu.europa.ec.eudi.openid4vp.AuthorizationResponsePayload
import eu.europa.ec.eudi.openid4vp.JarmSpec

internal object ResponseSignerEncryptor {
    fun signEncryptResponse(spec: JarmSpec, data: AuthorizationResponsePayload): String {
        return when (spec) {
            is JarmSpec.SignedResponseJarmSpec -> sign(spec, data)
            is JarmSpec.EncryptedResponseJarmSpec -> encrypt(spec, data)
            is JarmSpec.SignedAndEncryptedResponseJarmSpec -> signAndEncrypt(spec, data)
        }
    }

    fun sign(spec: JarmSpec.SignedResponseJarmSpec, data: AuthorizationResponsePayload): String {
        TODO("Not yet implemented")
    }

    fun encrypt(spec: JarmSpec.EncryptedResponseJarmSpec, data: AuthorizationResponsePayload): String {
        val jweEncrypter = deductEncryptor(spec.responseEncryptionAlg, spec.responseEncryptionEnc, spec.keySet)
        val jweHeader = JWEHeader(spec.responseEncryptionAlg, spec.responseEncryptionEnc)
        val encryptedJWT = EncryptedJWT(jweHeader, dataAsJwt(data))
        encryptedJWT.encrypt(jweEncrypter)
        return encryptedJWT.serialize()
    }

    private fun signAndEncrypt(
        spec: JarmSpec.SignedAndEncryptedResponseJarmSpec,
        data: AuthorizationResponsePayload
    ): String {
        TODO("Not yet implemented")
    }

    private fun deductSigner(signingAlg: JWSAlgorithm?): JWSSigner? {
        TODO("Not yet implemented")
    }

    private fun deductEncryptor(
        responseEncryptionAlg: JWEAlgorithm?,
        responseEncryptionEnc: EncryptionMethod?,
        keySet: JWKSet?
    ): JWEEncrypter? {
        if (responseEncryptionAlg == null || responseEncryptionEnc == null || keySet == null) {
            return null
        }
        return when {
            responseEncryptionAlg == JWEAlgorithm.ECDH_ES -> createECDHEncrypter(keySet)
            responseEncryptionAlg == JWEAlgorithm.RSA_OAEP_256 -> createRSAEncrypter(keySet)
            else -> throw RuntimeException(
                "Unsupported encryption algorithm ${responseEncryptionAlg}." +
                        " Currently supported algorithms are [ECDH_ES, RSA_OAEP_256]"
            )
        }
    }

    private fun createECDHEncrypter(keySet: JWKSet): ECDHEncrypter {
        // Look for a EC key in JWKSet
        val ecJWK = keySet.keys.first { it.keyType.value.equals(KeyType.EC) }
            ?: throw RuntimeException("Specified encryption algorithm is ECDH_ES but no EC public key provided")
        return ECDHEncrypter(ECKey.parse(ecJWK.toJSONObject()))
    }

    private fun createRSAEncrypter(keySet: JWKSet): RSAEncrypter {
        val rsaJWK = keySet.keys.first { it.keyType.value.equals(KeyType.RSA) }
            ?: throw RuntimeException("Specified encryption algorithm is RSA_OAEP_256 but no RSA public key provided")
        return RSAEncrypter(RSAKey.parse(rsaJWK.toJSONObject()))
    }

    private fun dataAsJwt(data: AuthorizationResponsePayload): JWTClaimsSet? {
        TODO("Not yet implemented")
    }
}
