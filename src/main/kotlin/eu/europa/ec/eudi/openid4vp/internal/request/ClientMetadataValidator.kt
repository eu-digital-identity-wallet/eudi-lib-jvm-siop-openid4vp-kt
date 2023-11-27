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
import io.ktor.client.call.*
import io.ktor.client.request.*
import java.io.IOException
import java.net.URL
import java.text.ParseException

internal class ClientMetadataValidator(
    private val walletOpenId4VPConfig: WalletOpenId4VPConfig,
    private val httpClientFactory: KtorHttpClientFactory = DefaultHttpClientFactory,
) {

    suspend fun validate(unvalidatedClientMetadata: UnvalidatedClientMetaData): Result<ClientMetaData> = runCatching {
        val jwkSets = parseRequiredJwks(unvalidatedClientMetadata).getOrThrow()
        val types = parseRequiredSubjectSyntaxTypes(unvalidatedClientMetadata).getOrThrow()
        val idTokenJWSAlg =
            parseRequiredSigningAlgorithm(unvalidatedClientMetadata.idTokenSignedResponseAlg).getOrThrow()
        val idTokenJWEAlg =
            parseRequiredEncryptionAlgorithm(unvalidatedClientMetadata.idTokenEncryptedResponseAlg).getOrThrow()
        val idTokenJWEEnc =
            parseRequiredEncryptionMethod(unvalidatedClientMetadata.idTokenEncryptedResponseEnc).getOrThrow()
        if ((
                !unvalidatedClientMetadata.authorizationEncryptedResponseAlg.isNullOrEmpty() &&
                    unvalidatedClientMetadata.authorizationEncryptedResponseEnc.isNullOrEmpty()
                ) ||
            (
                unvalidatedClientMetadata.authorizationEncryptedResponseAlg.isNullOrEmpty() &&
                    !unvalidatedClientMetadata.authorizationEncryptedResponseEnc.isNullOrEmpty()
                )
        ) {
            val msg = """Cannot construct ResponseSigningEncryptionSpec from client metadata:
                    property authorization_encrypted_response_alg exists 
                    but no property authorization_encrypted_response_enc found
            """.trimIndent()
            throw RuntimeException(msg)
        }

        val authSgnRespAlg: JWSAlgorithm? =
            parseOptionalSigningAlgorithm(
                unvalidatedClientMetadata.authorizationSignedResponseAlg,
            )
        val authEncRespAlg: JWEAlgorithm? =
            parseOptionalEncryptionAlgorithm(
                unvalidatedClientMetadata.authorizationEncryptedResponseAlg,
            )
        val authEncRespEnc: EncryptionMethod? =
            parseOptionalEncryptionMethod(
                unvalidatedClientMetadata.authorizationEncryptedResponseEnc,
            )

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

    @Suppress("ktlint")
    private fun parseOptionalSigningAlgorithm(signingAlg: String?): JWSAlgorithm? {
        if (signingAlg.isNullOrEmpty()) {
            return null
        }
        val parsedSigningAlg = JWSAlgorithm.parse(signingAlg)
        if (!walletOpenId4VPConfig.authorizationSigningAlgValuesSupported.contains(parsedSigningAlg)) {
            throw IllegalArgumentException("The Signing algorithm specified in received client metadata is not supported")
        }
        return parsedSigningAlg
    }

    @Suppress("ktlint")
    private fun parseOptionalEncryptionAlgorithm(encryptionAlg: String?): JWEAlgorithm? {
        if (encryptionAlg.isNullOrEmpty()) {
            return null
        }
        val parsedEncryptionAlgorithm = JWEAlgorithm.parse(encryptionAlg)
        if (!walletOpenId4VPConfig.authorizationEncryptionAlgValuesSupported.contains(parsedEncryptionAlgorithm)) {
            throw IllegalArgumentException("The Encryption algorithm specified in received client metadata is not supported")
        }
        return parsedEncryptionAlgorithm
    }

    @Suppress("ktlint")
    private fun parseOptionalEncryptionMethod(encryptionMethod: String?): EncryptionMethod? {
        if (encryptionMethod.isNullOrEmpty()) {
            return null
        }
        val parsedEncryptionMethodAlgorithm = EncryptionMethod.parse(encryptionMethod)
        if (!walletOpenId4VPConfig.authorizationEncryptionEncValuesSupported.contains(parsedEncryptionMethodAlgorithm)) {
            throw UnsupportedOperationException("The Encryption Encoding method specified in received client metadata is not supported")
        }
        return parsedEncryptionMethodAlgorithm
    }

    @Suppress("ktlint")
    private fun parseRequiredSigningAlgorithm(signingAlg: String?): Result<JWSAlgorithm> =
        if (signingAlg.isNullOrEmpty()) RequestValidationError.IdTokenSigningAlgMissing.asFailure()
        else Result.success(JWSAlgorithm.parse(signingAlg))

    @Suppress("ktlint")
    private fun parseRequiredEncryptionAlgorithm(encryptionAlg: String?): Result<JWEAlgorithm> =
        if (encryptionAlg.isNullOrEmpty()) RequestValidationError.IdTokenEncryptionAlgMissing.asFailure()
        else Result.success(JWEAlgorithm.parse(encryptionAlg))

    @Suppress("ktlint")
    private fun parseRequiredEncryptionMethod(encryptionMethod: String?): Result<EncryptionMethod> =
        if (encryptionMethod.isNullOrEmpty()) RequestValidationError.IdTokenEncryptionMethodMissing.asFailure()
        else Result.success(EncryptionMethod.parse(encryptionMethod))

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
            ResolutionError.ClientMetadataJwkUriUnparsable(ex).asFailure()
        }

        suspend fun requiredJwksUri() = try {
            val unparsed = httpClientFactory().use { client ->
                client.get(URL(clientMetadata.jwksUri)).body<String>()
            }
            val jwkSet = JWKSet.parse(unparsed)
            Result.success(jwkSet)
        } catch (ex: IOException) {
            ResolutionError.ClientMetadataJwkResolutionFailed(ex).asFailure()
        } catch (ex: ParseException) {
            ResolutionError.ClientMetadataJwkResolutionFailed(ex).asFailure()
        }

        return when {
            clientMetadata.jwksUri.isNullOrEmpty() -> requiredJwks()
            else -> requiredJwksUri()
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
        } else {
            RequestValidationError.SubjectSyntaxTypesWrongSyntax.asFailure()
        }
    }
}
