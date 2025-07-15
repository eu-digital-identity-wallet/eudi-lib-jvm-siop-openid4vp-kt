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
import com.nimbusds.jose.jwk.JWKSet
import com.nimbusds.jose.jwk.ThumbprintURI
import eu.europa.ec.eudi.openid4vp.*
import eu.europa.ec.eudi.openid4vp.internal.ensure
import eu.europa.ec.eudi.openid4vp.internal.jsonSupport
import io.ktor.client.*
import io.ktor.client.call.*
import io.ktor.client.request.*
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.JsonObject
import java.text.ParseException

internal object ClientMetaDataValidator {

    @Throws(AuthorizationRequestException::class)
    fun validateClientMetaData(unvalidated: UnvalidatedClientMetaData): ValidatedClientMetaData {
        val types = subjectSyntaxTypes(unvalidated.subjectSyntaxTypesSupported)

        val jwkSet = jwkSet(unvalidated)
        val responseEncryptionMethodsSupported = responseEncryptionMethodsSupported(unvalidated)

        val vpFormats = vpFormats(unvalidated)

        return ValidatedClientMetaData(
            jwkSet = jwkSet,
            subjectSyntaxTypesSupported = types,
            responseEncryptionMethodsSupported = responseEncryptionMethodsSupported,
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

private fun jwkSet(unvalidated: UnvalidatedClientMetaData): JWKSet? {
    fun JsonObject.asJWKSet(): JWKSet = try {
        JWKSet.parse(jsonSupport.encodeToString(this))
    } catch (ex: ParseException) {
        throw ResolutionError.ClientMetadataJwksUnparsable(ex).asException()
    }

    val jwks = unvalidated.jwks?.asJWKSet()
    if (null != jwks) {
        ensure(jwks.keys.isNotEmpty()) {
            RequestValidationError.InvalidClientMetaData("'${OpenId4VPSpec.JWKS}' cannot be empty").asException()
        }
        ensure(jwks.keys.all { jwk -> null != jwk.keyID && null != jwk.algorithm }) {
            RequestValidationError.InvalidClientMetaData("All JWKS must have `kid` and `alg`").asException()
        }
        val keyIds = jwks.keys.map { it.keyID }
        ensure(keyIds.size == keyIds.toSet().size) {
            RequestValidationError.InvalidClientMetaData("Each JWK must have a unique `kid`").asException()
        }
    }

    return jwks
}

private fun responseEncryptionMethodsSupported(unvalidated: UnvalidatedClientMetaData): List<EncryptionMethod>? {
    val encryptionMethods = unvalidated.responseEncryptionMethodsSupported?.map { EncryptionMethod.parse(it) }
    if (null != encryptionMethods) {
        ensure(encryptionMethods.isNotEmpty()) {
            RequestValidationError.InvalidClientMetaData(
                "'${OpenId4VPSpec.RESPONSE_ENCRYPTION_METHODS_SUPPORTED}' must not be empty",
            ).asException()
        }
    }

    return encryptionMethods ?: OpenId4VPSpec.RESPONSE_ENCRYPTION_METHODS_SUPPORTED_DEFAULT
}

private fun vpFormats(unvalidated: UnvalidatedClientMetaData): VpFormats =
    try {
        unvalidated.vpFormats.toDomain()
    } catch (_: IllegalArgumentException) {
        throw RequestValidationError.InvalidClientMetaData("Invalid vp_format").asException()
    }
