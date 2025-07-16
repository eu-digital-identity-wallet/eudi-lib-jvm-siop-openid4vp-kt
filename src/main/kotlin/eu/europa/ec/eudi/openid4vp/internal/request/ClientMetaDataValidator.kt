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
package eu.europa.ec.eudi.openid4vp.internal.request

import com.nimbusds.jose.EncryptionMethod
import com.nimbusds.jose.jwk.JWK
import com.nimbusds.jose.jwk.JWKSet
import com.nimbusds.jose.jwk.ThumbprintURI
import eu.europa.ec.eudi.openid4vp.*
import eu.europa.ec.eudi.openid4vp.RequestValidationError.UnsupportedClientMetaData
import eu.europa.ec.eudi.openid4vp.internal.ensure
import eu.europa.ec.eudi.openid4vp.internal.jsonSupport
import eu.europa.ec.eudi.openid4vp.internal.response.EncrypterFactory
import io.ktor.client.*
import io.ktor.client.call.*
import io.ktor.client.request.*
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.JsonObject
import java.text.ParseException

internal object ClientMetaDataValidator {

    @Throws(AuthorizationRequestException::class)
    fun validateClientMetaData(
        unvalidated: UnvalidatedClientMetaData,
        responseMode: ResponseMode,
        responseEncryptionConfiguration: ResponseEncryptionConfiguration,
    ): ValidatedClientMetaData {
        val types = subjectSyntaxTypes(unvalidated.subjectSyntaxTypesSupported)

        val verifierAdvertisedKeys = jwks(unvalidated)
        val verifierSupportedEncryptionMethods = responseEncryptionMethodsSupported(unvalidated)

        val responseEncryptionSpecification =
            if (!responseMode.requiresEncryption()) null
            else responseEncryptionConfiguration.responseEncryptionSpecification(
                verifierAdvertisedKeys,
                verifierSupportedEncryptionMethods ?: OpenId4VPSpec.RESPONSE_ENCRYPTION_METHODS_SUPPORTED_DEFAULT.toSet(),
            )

        val vpFormats = vpFormats(unvalidated)

        return ValidatedClientMetaData(
            responseEncryptionSpecification = responseEncryptionSpecification,
            subjectSyntaxTypesSupported = types,
            vpFormats = vpFormats,
        )
    }
}

private fun subjectSyntaxTypes(subjectSyntaxTypesSupported: List<String>?): List<SubjectSyntaxType> {
    fun subjectSyntax(value: String) =
        parseSubjectSyntaxType(value)
            ?: throw RequestValidationError.SubjectSyntaxTypesWrongSyntax.asException()

    return subjectSyntaxTypesSupported?.map { subjectSyntax(it) } ?: emptyList()
}

private fun parseSubjectSyntaxType(value: String): SubjectSyntaxType? {
    fun isDecentralizedIdentifier(): Boolean =
        !(value.isEmpty() || value.count { it == ':' } != 1 || value.split(':').any { it.isEmpty() })

    fun parseDecentralizedIdentifier(): SubjectSyntaxType.DecentralizedIdentifier =
        when {
            value.isEmpty() -> error("Cannot create DID from $value: Empty value passed")
            value.count { it == ':' } != 1 -> error("Cannot create DID from $value: Wrong syntax")
            value.split(':')
                .any { it.isEmpty() } -> error("Cannot create DID from $value: DID components cannot be empty")

            else -> SubjectSyntaxType.DecentralizedIdentifier(value.split(':')[1])
        }

    fun isJWKThumbprint(): Boolean = value != ThumbprintURI.PREFIX

    return when {
        isJWKThumbprint() -> SubjectSyntaxType.JWKThumbprint
        isDecentralizedIdentifier() -> parseDecentralizedIdentifier()
        else -> null
    }
}

private fun jwks(unvalidated: UnvalidatedClientMetaData): List<JWK> {
    fun JsonObject.asJWKSet(): JWKSet = try {
        JWKSet.parse(jsonSupport.encodeToString(this))
    } catch (ex: ParseException) {
        throw ResolutionError.ClientMetadataJwksUnparsable(ex).asException()
    }

    val jwkSet = unvalidated.jwks?.asJWKSet()
    if (null != jwkSet) {
        ensure(jwkSet.keys.isNotEmpty()) {
            RequestValidationError.InvalidClientMetaData("'${OpenId4VPSpec.JWKS}' cannot be empty").asException()
        }

        val keyIds = jwkSet.keys.map { it.keyID }
        ensure(keyIds.size == keyIds.toSet().size) {
            RequestValidationError.InvalidClientMetaData("Each JWK must have a unique `kid`").asException()
        }
    }

    return jwkSet?.keys
        ?.filter { !it.keyID.isNullOrBlank() && !it.algorithm?.name.isNullOrBlank() }
        .orEmpty()
}

private fun responseEncryptionMethodsSupported(unvalidated: UnvalidatedClientMetaData): Set<EncryptionMethod>? {
    val encryptionMethods = unvalidated.responseEncryptionMethodsSupported?.map { EncryptionMethod.parse(it) }
    if (null != encryptionMethods) {
        ensure(encryptionMethods.isNotEmpty()) {
            RequestValidationError.InvalidClientMetaData(
                "'${OpenId4VPSpec.RESPONSE_ENCRYPTION_METHODS_SUPPORTED}' must not be empty",
            ).asException()
        }
    }

    return encryptionMethods?.toSet()
}

private fun vpFormats(unvalidated: UnvalidatedClientMetaData): VpFormats =
    try {
        unvalidated.vpFormats.toDomain()
    } catch (_: IllegalArgumentException) {
        throw RequestValidationError.InvalidClientMetaData("Invalid vp_format").asException()
    }

/**
 * Method checks whether Wallet can fulfill the Verifier's authorization response encryption requirements.
 *
 * @param verifierAdvertisedKeys the JWKS advertised by the Verifier in his Client Metadata
 * @param verifierSupportedEncryptionMethods the EncryptionMethods advertised by the Verifier in his Client Metadata
 * @receiver the wallet's [ResponseEncryptionConfiguration] encryption parameters supported by the Wallet
 *
 * @return [ResponseEncryptionSpecification] the encryption parameters that can be used by the Wallet to fulfill the
 * Verifier's encryption requirements
 * @throws AuthorizationRequestException in case the Wallet does not support any of the encryption parameters that
 * can fulfill the Verifier's  encryption requirements
 */
@Throws(AuthorizationRequestException::class)
private fun ResponseEncryptionConfiguration.responseEncryptionSpecification(
    verifierAdvertisedKeys: List<JWK>,
    verifierSupportedEncryptionMethods: Set<EncryptionMethod>,
): ResponseEncryptionSpecification {
    ensure(this is ResponseEncryptionConfiguration.Supported) {
        UnsupportedClientMetaData("Wallet doesn't support encrypting authorization responses").asException()
    }

    val encryptionMethod = supportedMethods.firstOrNull {
        it in verifierSupportedEncryptionMethods
    } ?: throw UnsupportedClientMetaData("Wallet doesn't support any of the encryption methods supported by verifier").asException()

    val (encryptionAlgorithm, encryptionKey) = supportedAlgorithms.firstNotNullOfOrNull { supportedAlgorithm ->
        val encryptionKey = verifierAdvertisedKeys.firstOrNull { key ->
            supportedAlgorithm.name == key.algorithm?.name && EncrypterFactory.canBeUsed(supportedAlgorithm, key)
        }

        if (null != encryptionKey) {
            supportedAlgorithm to encryptionKey
        } else {
            null
        }
    } ?: throw UnsupportedClientMetaData("Wallet doesn't support any of the encryption algorithms supported by verifier").asException()

    return ResponseEncryptionSpecification(encryptionAlgorithm, encryptionMethod, encryptionKey)
}
