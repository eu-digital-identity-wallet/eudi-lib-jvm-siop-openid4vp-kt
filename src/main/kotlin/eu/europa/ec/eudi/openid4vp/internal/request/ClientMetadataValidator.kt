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
import com.nimbusds.openid.connect.sdk.rp.OIDCClientMetadata
import eu.europa.ec.eudi.openid4vp.*
import eu.europa.ec.eudi.openid4vp.internal.success
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.withContext
import java.io.IOException
import java.net.URL
import java.text.ParseException

internal class ClientMetadataValidator(private val ioCoroutineDispatcher: CoroutineDispatcher) {

    suspend fun validate(clientMetadata: ClientMetaData): Result<OIDCClientMetadata> = runCatching {
        val jwkSets = parseRequiredJwks(clientMetadata).getOrThrow()
        val types = parseRequiredSubjectSyntaxTypes(clientMetadata).getOrThrow()
        if (clientMetadata.authorizationEncryptedResponseAlg != null &&
            clientMetadata.authorizationEncryptedResponseEnc == null
        ) {
            throw RuntimeException(
                "Cannot construct ResponseSigningEncryptionSpec from client metadata:" +
                    " property authorization_encrypted_response_alg exists but no property authorization_encrypted_response_enc found",
            )
        }
        // TODO: Find if signing/encryption algs match the supported ones
        val authSgnRespAlg: JWSAlgorithm? = clientMetadata.authorizationSignedResponseAlg?.let { JWSAlgorithm.parse(it) }
        val authEncRespAlg: JWEAlgorithm? = clientMetadata.authorizationEncryptedResponseAlg?.let { JWEAlgorithm.parse(it) }
        val authEncRespEnc: EncryptionMethod? = clientMetadata.authorizationEncryptedResponseEnc?.let { EncryptionMethod.parse(it) }

        OIDCClientMetadata().apply {
            idTokenJWSAlg = JWSAlgorithm.parse(clientMetadata.idTokenSignedResponseAlg)
            idTokenJWEAlg = JWEAlgorithm.parse(clientMetadata.idTokenEncryptedResponseAlg)
            idTokenJWEEnc = EncryptionMethod.parse(clientMetadata.idTokenEncryptedResponseEnc)
            jwkSet = jwkSets
            setCustomField("subject_syntax_types_supported", types)
            authSgnRespAlg?.let { setCustomField("authorization_signed_response_alg", it) }
            authEncRespAlg?.let { setCustomField("authorization_encrypted_response_alg", it) }
            authEncRespEnc?.let { setCustomField("authorization_encrypted_response_enc", it) }
        }
    }

    private suspend fun parseRequiredJwks(clientMetadata: ClientMetaData): Result<JWKSet> {
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

    private fun parseRequiredSubjectSyntaxTypes(clientMetadata: ClientMetaData): Result<List<SubjectSyntaxType>> {
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
