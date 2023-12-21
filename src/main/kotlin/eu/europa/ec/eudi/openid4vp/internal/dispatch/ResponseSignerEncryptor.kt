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
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.*
import java.time.Instant

internal object ResponseSignerEncryptor {

    /**
     * Signs the [response to be sent to the verifier][data] according ot the [spec]
     *
     * @param data the response to be sent to the verifier, that needs to be signed
     * @param spec the specification of how to create the JARM response
     *
     * @return a JWT containing the [data] which depending on the [spec] it could be
     * - a signed JWT
     * - an encrypted JWT
     * - an encrypted JWT containing a signed JWT
     */
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
        val (signingAlg, signer) = option
        val header = JWSHeader.Builder(signingAlg)
            .keyID(signer.getKeyId())
            .build()
        val dataAsJWT = JwtPayloadFactory.create(data, holderId, Instant.now())
        return SignedJWT(header, dataAsJWT).apply { sign(signer) }
    }

    private fun encrypt(
        holderId: String,
        option: JarmOption.EncryptedResponse,
        data: AuthorizationResponsePayload,
    ): EncryptedJWT {
        val (jweAlgorithm, encryptionMethod, encryptionKeySet) = option
        val (_, jweEncrypter) = keyAndEncryptor(jweAlgorithm, encryptionKeySet)
        val jweHeader = JWEHeader(jweAlgorithm, encryptionMethod)
        val dataAsJWT = JwtPayloadFactory.create(data, holderId, Instant.now())
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

    private fun keyAndEncryptor(
        jweAlgorithm: JWEAlgorithm,
        jwkSet: JWKSet,
    ): Pair<JWK, JWEEncrypter> =
        EncrypterFactory
            .findEncrypters(jweAlgorithm, jwkSet)
            .firstNotNullOfOrNull { it.toPair() }
            ?: error("Cannot find appropriate encryption key for ${jweAlgorithm.name}")
}

private object JwtPayloadFactory {

    private const val PRESENTATION_SUBMISSION_CLAIM = "presentation_submission"
    private const val VP_TOKEN_CLAIM = "vp_token"
    private const val STATE_CLAIM = "state"
    private const val ID_TOKEN_CLAIM = "id_token"
    private const val ERROR_CLAIM = "error"
    private const val ERROR_DESCRIPTION_CLAIM = "error_description"
    fun create(data: AuthorizationResponsePayload, holderId: String, issuedAt: Instant): JWTClaimsSet =
        buildJsonObject {
            put("iss", holderId)
            put("iat", issuedAt.epochSecond)
            put("aud", data.clientId)
            put(STATE_CLAIM, data.state)

            when (data) {
                is AuthorizationResponsePayload.SiopAuthentication -> {
                    put(ID_TOKEN_CLAIM, data.idToken)
                }

                is AuthorizationResponsePayload.OpenId4VPAuthorization -> {
                    put(VP_TOKEN_CLAIM, data.vpToken)
                    put(PRESENTATION_SUBMISSION_CLAIM, Json.encodeToJsonElement(data.presentationSubmission))
                }

                is AuthorizationResponsePayload.SiopOpenId4VPAuthentication -> {
                    put(ID_TOKEN_CLAIM, data.idToken)
                    put(VP_TOKEN_CLAIM, data.vpToken)
                    put(PRESENTATION_SUBMISSION_CLAIM, Json.encodeToJsonElement(data.presentationSubmission))
                }

                is AuthorizationResponsePayload.InvalidRequest -> {
                    put(ERROR_CLAIM, AuthorizationRequestErrorCode.fromError(data.error).code)
                    put(ERROR_DESCRIPTION_CLAIM, "${data.error}")
                }

                is AuthorizationResponsePayload.NoConsensusResponseData -> {
                    put(ERROR_CLAIM, AuthorizationRequestErrorCode.USER_CANCELLED.code)
                }
            }
        }.asJWTClaimSet()
    private fun JsonObject.asJWTClaimSet(): JWTClaimsSet {
        val jsonStr = Json.encodeToString(this)
        return JWTClaimsSet.parse(jsonStr)
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
