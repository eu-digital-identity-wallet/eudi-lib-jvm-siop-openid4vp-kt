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
package eu.europa.ec.eudi.openid4vp.internal.response

import com.nimbusds.jose.*
import com.nimbusds.jose.JWEAlgorithm.Family
import com.nimbusds.jose.crypto.ECDHEncrypter
import com.nimbusds.jose.crypto.RSAEncrypter
import com.nimbusds.jose.jwk.ECKey
import com.nimbusds.jose.jwk.JWK
import com.nimbusds.jose.jwk.RSAKey
import com.nimbusds.jose.util.Base64URL
import com.nimbusds.jwt.EncryptedJWT
import com.nimbusds.jwt.JWTClaimsSet
import com.nimbusds.jwt.SignedJWT
import com.nimbusds.oauth2.sdk.id.Issuer
import eu.europa.ec.eudi.openid4vp.*
import eu.europa.ec.eudi.openid4vp.dcql.QueryId
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.*
import java.time.Duration
import java.time.Instant

/**
 * Creates according to the [verifier's requirements][jarmRequirement], a JARM JWT which encapsulates
 * the provided [data]
 *
 * @param data the response to be sent to the verifier
 * @receiver the wallet configuration
 * @return a JWT containing the [data] which depending on the [jarmRequirement] it could be
 * - a signed JWT
 * - an encrypted JWT
 * - an encrypted JWT containing a signed JWT
 *
 * @throws IllegalStateException in case the wallet configuration doesn't support the [jarmRequirement]
 * @throws JOSEException
 */
@Throws(IllegalStateException::class, JOSEException::class)
internal fun SiopOpenId4VPConfig.jarmJwt(
    jarmRequirement: JarmRequirement,
    data: AuthorizationResponsePayload,
): Jwt = when (jarmRequirement) {
    is JarmRequirement.Signed -> sign(jarmRequirement, data)
    is JarmRequirement.Encrypted -> encrypt(jarmRequirement, data)
    is JarmRequirement.SignedAndEncrypted -> signAndEncrypt(jarmRequirement, data)
}.serialize()

private fun SiopOpenId4VPConfig.sign(
    requirement: JarmRequirement.Signed,
    data: AuthorizationResponsePayload,
): SignedJWT {
    val signingCfg = jarmConfiguration.signingConfig()
    checkNotNull(signingCfg) { "Wallet doesn't support signing JARM" }

    val header = JWSHeader.Builder(requirement.responseSigningAlg)
        .keyID(signingCfg.signer.getKeyId())
        .build()

    val claimSet = JwtPayloadFactory.signedJwtClaimSet(data, issuer, Instant.now(), signingCfg.ttl)
    return SignedJWT(header, claimSet).apply { sign(signingCfg.signer) }
}

private fun SiopOpenId4VPConfig.encrypt(
    requirement: JarmRequirement.Encrypted,
    data: AuthorizationResponsePayload,
): EncryptedJWT {
    val encryptionCfg = jarmConfiguration.encryptionConfig()
    checkNotNull(encryptionCfg) { "Wallet doesn't support encrypted JARM" }

    val (jweAlgorithm, encryptionMethod, verifierKey) = requirement
    val jweEncrypter = EncrypterFactory.createEncrypter(jweAlgorithm, verifierKey)
    val jweHeader = jweHeader(jweAlgorithm, encryptionMethod, verifierKey, data)

    val claimSet = JwtPayloadFactory.encryptedJwtClaimSet(data)
    return EncryptedJWT(jweHeader, claimSet).apply { encrypt(jweEncrypter) }
}

private fun jweHeader(
    jweAlgorithm: JWEAlgorithm,
    encryptionMethod: EncryptionMethod,
    recipientKey: JWK,
    data: AuthorizationResponsePayload,
    builderAction: JWEHeader.Builder.() -> Unit = {},
): JWEHeader {
    if (jweAlgorithm in Family.ECDH_ES) {
        require(data.encryptionParameters is EncryptionParameters.DiffieHellman) {
            "Diffie-Hellman encryption parameters are required for ${jweAlgorithm.name}"
        }
    }

    val (apv, apu) = when (val encryptionParameters = data.encryptionParameters) {
        is EncryptionParameters.DiffieHellman -> encryptionParameters.apu
        else -> null
    }?.let { Base64URL.encode(data.nonce) to it } ?: (null to null)

    return JWEHeader.Builder(jweAlgorithm, encryptionMethod)
        .apply {
            builderAction()
            apv?.let(::agreementPartyVInfo)
            apu?.let(::agreementPartyUInfo)
            recipientKey.toPublicJWK().keyID?.let(::keyID)
        }
        .build()
}

private fun SiopOpenId4VPConfig.signAndEncrypt(
    requirement: JarmRequirement.SignedAndEncrypted,
    data: AuthorizationResponsePayload,
): JWEObject {
    check(jarmConfiguration is JarmConfiguration.SigningAndEncryption) {
        "Wallet doesn't support signing & encrypting JARM"
    }

    val signedJwt = sign(requirement.signed, data)
    val (jweAlgorithm, encryptionMethod, verifierKey) = requirement.encryptResponse
    val jweEncrypter = EncrypterFactory.createEncrypter(jweAlgorithm, verifierKey)
    val jweHeader = jweHeader(jweAlgorithm, encryptionMethod, verifierKey, data) {
        contentType("JWT")
    }

    return JWEObject(jweHeader, Payload(signedJwt)).apply { encrypt(jweEncrypter) }
}

private object JwtPayloadFactory {

    private const val PRESENTATION_SUBMISSION_CLAIM = "presentation_submission"
    private const val VP_TOKEN_CLAIM = "vp_token"
    private const val STATE_CLAIM = "state"
    private const val ID_TOKEN_CLAIM = "id_token"
    private const val ERROR_CLAIM = "error"
    private const val ERROR_DESCRIPTION_CLAIM = "error_description"
    fun encryptedJwtClaimSet(data: AuthorizationResponsePayload): JWTClaimsSet =
        buildJsonObject {
            payloadClaims(data)
        }.asJWTClaimSet()

    fun signedJwtClaimSet(
        data: AuthorizationResponsePayload,
        issuer: Issuer?,
        issuedAt: Instant,
        ttl: Duration?,
    ): JWTClaimsSet =
        buildJsonObject {
            issuer?.let { put("iss", it.value) }
            when (data) {
                is AuthorizationResponsePayload.Positive -> put("aud", data.clientId.toString())
                is AuthorizationResponsePayload.Negative -> put("aud", data.clientId.toString())
                is AuthorizationResponsePayload.InvalidRequest -> {}
            }
            ttl?.let {
                val exp = issuedAt.plusMillis(ttl.toMillis()).epochSecond
                put("exp", exp)
            }
            payloadClaims(data)
        }.asJWTClaimSet()

    private fun JsonObjectBuilder.payloadClaims(data: AuthorizationResponsePayload) {
        data.state?.let {
            put(STATE_CLAIM, it)
        }
        when (data) {
            is AuthorizationResponsePayload.SiopAuthentication -> {
                put(ID_TOKEN_CLAIM, data.idToken)
            }

            is AuthorizationResponsePayload.OpenId4VPAuthorization -> {
                put(data.vpContent)
            }

            is AuthorizationResponsePayload.SiopOpenId4VPAuthentication -> {
                put(ID_TOKEN_CLAIM, data.idToken)
                put(data.vpContent)
            }

            is AuthorizationResponsePayload.InvalidRequest -> {
                put(ERROR_CLAIM, AuthorizationRequestErrorCode.fromError(data.error).code)
                put(ERROR_DESCRIPTION_CLAIM, "${data.error}")
            }

            is AuthorizationResponsePayload.NoConsensusResponseData -> {
                put(ERROR_CLAIM, AuthorizationRequestErrorCode.ACCESS_DENIED.code)
            }
        }
    }

    fun JsonObjectBuilder.put(vpContent: VpContent) {
        when (vpContent) {
            is VpContent.PresentationExchange -> {
                put(VP_TOKEN_CLAIM, vpContent.verifiablePresentations.toJson())
                put(PRESENTATION_SUBMISSION_CLAIM, Json.encodeToJsonElement(vpContent.presentationSubmission))
            }

            is VpContent.DCQL -> put(VP_TOKEN_CLAIM, vpContent.verifiablePresentations.toJson())
        }
    }

    private fun JsonObject.asJWTClaimSet(): JWTClaimsSet {
        val jsonStr = Json.encodeToString(this)
        return JWTClaimsSet.parse(jsonStr)
    }
}

internal fun Map<QueryId, VerifiablePresentation>.toJson() =
    buildJsonObject {
        for ((key, value) in iterator()) {
            put(key.value, value.asJson())
        }
    }

internal fun List<VerifiablePresentation>.toJson(): JsonElement {
    fun VerifiablePresentation.asJson(): JsonElement {
        return when (this) {
            is VerifiablePresentation.Generic -> JsonPrimitive(value)
            is VerifiablePresentation.JsonObj -> value
        }
    }

    return when (size) {
        1 -> first().asJson()
        0 -> error("Not expected")
        else -> {
            buildJsonArray {
                for (vp in iterator()) {
                    add(vp.asJson())
                }
            }
        }
    }
}
internal object EncrypterFactory {

    fun createEncrypter(
        algorithm: JWEAlgorithm,
        recipientKey: JWK,
    ): JWEEncrypter =
        createEncrypterOrNull(algorithm, recipientKey)
            ?: error("Cannot find appropriate encryption key for ${algorithm.name}")

    fun createEncrypterOrNull(
        algorithm: JWEAlgorithm,
        recipientKey: JWK,
    ): JWEEncrypter? =
        familyOf(algorithm)?.let { family ->
            when {
                family == Family.ECDH_ES && recipientKey is ECKey -> ECDHEncrypter(recipientKey)
                family == Family.RSA && recipientKey is RSAKey -> RSAEncrypter(recipientKey)
                else -> null
            }
        }
    fun canBeUsed(algorithm: JWEAlgorithm, candidateRecipientKey: JWK): Boolean {
        return familyOf(algorithm)?.let { family ->
            when {
                family == Family.ECDH_ES && candidateRecipientKey is ECKey -> true
                family == Family.RSA && candidateRecipientKey is RSAKey -> true
                else -> false
            }
        } == true
    }

    private val SupportedFamilies = listOf(Family.ECDH_ES, Family.RSA)
    private fun familyOf(algorithm: JWEAlgorithm): Family? =
        SupportedFamilies.firstOrNull { family -> family.contains(algorithm) }
}
