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
import com.nimbusds.jose.JWEAlgorithm
import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.jwk.JWKSet
import eu.europa.ec.eudi.openid4vp.*
import eu.europa.ec.eudi.openid4vp.internal.success
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.withContext
import java.io.IOException
import java.net.URL
import java.text.ParseException

internal class ClientMetadataValidator(private val ioCoroutineDispatcher: CoroutineDispatcher) {

    suspend fun validate(unvalidatedClientMetadata: UnvalidatedClientMetaData): Result<ClientMetaData> = runCatching {
        val jwkSets = parseRequiredJwks(unvalidatedClientMetadata).getOrThrow()
        val types = parseRequiredSubjectSyntaxTypes(unvalidatedClientMetadata).getOrThrow()
        val idTokenJWSAlg = parseRequiredSigningAlgorithm(unvalidatedClientMetadata.idTokenSignedResponseAlg).getOrThrow()
        val idTokenJWEAlg = parseRequiredEncryptionAlgorithm(unvalidatedClientMetadata.idTokenEncryptedResponseAlg).getOrThrow()
        val idTokenJWEEnc = parseRequiredEncryptionMethod(unvalidatedClientMetadata.idTokenEncryptedResponseEnc).getOrThrow()
        if (!unvalidatedClientMetadata.authorizationEncryptedResponseAlg.isNullOrEmpty() &&
            unvalidatedClientMetadata.authorizationEncryptedResponseEnc.isNullOrEmpty()
        ) {
            throw RuntimeException(
                "Cannot construct ResponseSigningEncryptionSpec from client metadata:" +
                        " property authorization_encrypted_response_alg exists but no property authorization_encrypted_response_enc found",
            )
        }
        val authSgnRespAlg: JWSAlgorithm? =
            parseOptionalSigningAlgorithm(unvalidatedClientMetadata.authorizationSignedResponseAlg)
        val authEncRespAlg: JWEAlgorithm? =
            parseOptionalEncryptionAlgorithm(unvalidatedClientMetadata.authorizationEncryptedResponseAlg)
        val authEncRespEnc: EncryptionMethod? =
            parseOptionalEncryptionMethod(unvalidatedClientMetadata.authorizationEncryptedResponseEnc)

        // TODO: Find if signing/encryption algs match the supported ones

        ClientMetaData(
            idTokenJWSAlg = idTokenJWSAlg,
            idTokenJWEAlg = idTokenJWEAlg,
            idTokenJWEEnc = idTokenJWEEnc,
            jwkSet = jwkSets,
            subjectSyntaxTypesSupported = types,
            authorizationSignedResponseAlg = authSgnRespAlg,
            authorizationEncryptedResponseAlg = authEncRespAlg,
            authorizationEncryptedResponseEnc = authEncRespEnc,
        )
    }

    private fun parseOptionalSigningAlgorithm(signingAlg: String?): JWSAlgorithm? {
        return if (signingAlg.isNullOrEmpty()) null
        else JWSAlgorithm.parse(signingAlg)
    }

    private fun parseOptionalEncryptionAlgorithm(encryptionAlg: String?): JWEAlgorithm? {
        return if (encryptionAlg.isNullOrEmpty()) null
        else JWEAlgorithm.parse(encryptionAlg)
    }

    private fun parseOptionalEncryptionMethod(encryptionMethod: String?): EncryptionMethod? {
        return if (encryptionMethod.isNullOrEmpty()) null
        else EncryptionMethod.parse(encryptionMethod)
    }

    private fun parseRequiredSigningAlgorithm(signingAlg: String?): Result<JWSAlgorithm> {
        return if (signingAlg.isNullOrEmpty()) {
            RequestValidationError.IdTokenSigningAlgMissing.asFailure()
        } else {
            Result.success(JWSAlgorithm.parse(signingAlg))
        }
    }

    private fun parseRequiredEncryptionAlgorithm(encryptionAlg: String?): Result<JWEAlgorithm> {
        return if (encryptionAlg.isNullOrEmpty()) {
            RequestValidationError.IdTokenEncryptionAlgMissing.asFailure()
        } else {
            Result.success(JWEAlgorithm.parse(encryptionAlg))
        }
    }

    private fun parseRequiredEncryptionMethod(encryptionMethod: String?): Result<EncryptionMethod> {
        return if (encryptionMethod.isNullOrEmpty()) {
            RequestValidationError.IdTokenEncryptionMethodMissing.asFailure()
        } else {
            Result.success(EncryptionMethod.parse(encryptionMethod))
        }
    }

    private suspend fun parseRequiredJwks(clientMetadata: UnvalidatedClientMetaData): Result<JWKSet> {
        val atLeastOneJwkSourceDefined = !clientMetadata.jwks.isNullOrEmpty() || !clientMetadata.jwksUri.isNullOrEmpty()
        if (!atLeastOneJwkSourceDefined) {
            return RequestValidationError.MissingClientMetadataJwksSource.asFailure()
        }

        val bothJwksSourcesDefined = !clientMetadata.jwks.isNullOrEmpty() && !clientMetadata.jwksUri.isNullOrEmpty()
        if (bothJwksSourcesDefined) {
            return RequestValidationError.BothJwkUriAndInlineJwks.asFailure()
        }
        fun requiredJwks() = try {
            Result.success(JWKSet.parse(clientMetadata.jwks?.toString()))
        } catch (ex: ParseException) {
            ResolutionError.ClientMetadataJwkUriUnparsable(ex)
                .asFailure()
        }

        fun requiredJwksUri() = try {
            Result.success(JWKSet.load(URL(clientMetadata.jwksUri)))
        } catch (ex: IOException) {
            ResolutionError.ClientMetadataJwkResolutionFailed(ex)
                .asFailure()
        } catch (ex: ParseException) {
            ResolutionError.ClientMetadataJwkResolutionFailed(ex)
                .asFailure()
        }

        return when {
            clientMetadata.jwksUri.isNullOrEmpty() -> requiredJwks()
            else -> withContext(ioCoroutineDispatcher) { requiredJwksUri() }
        }
    }

    private fun parseRequiredSubjectSyntaxTypes(clientMetadata: UnvalidatedClientMetaData): Result<List<SubjectSyntaxType>> {
        val listNotEmpty = clientMetadata.subjectSyntaxTypesSupported.isNotEmpty()
        val allValidTypes = clientMetadata.subjectSyntaxTypesSupported.all(SubjectSyntaxType::isValid)
        fun String.asSubjectSyntaxType(): SubjectSyntaxType = when {
            SubjectSyntaxType.JWKThumbprint.isValid(this) -> SubjectSyntaxType.JWKThumbprint
            else -> SubjectSyntaxType.DecentralizedIdentifier.parse(this)
        }
        return if (listNotEmpty && allValidTypes) {
            clientMetadata.subjectSyntaxTypesSupported.map { it.asSubjectSyntaxType() }.success()
        } else RequestValidationError.SubjectSyntaxTypesWrongSyntax.asFailure()
    }
}
