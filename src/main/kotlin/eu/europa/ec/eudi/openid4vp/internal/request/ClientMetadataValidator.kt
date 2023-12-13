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
import io.ktor.client.call.*
import io.ktor.client.request.*
import java.io.IOException
import java.lang.RuntimeException
import java.net.URL
import java.text.ParseException

internal class ClientMetadataValidator(
    private val walletOpenId4VPConfig: WalletOpenId4VPConfig,
    private val httpClientFactory: KtorHttpClientFactory = DefaultHttpClientFactory,
) {

    suspend fun validate(unvalidated: UnvalidatedClientMetaData): ClientMetaData {
        val jwkSets = jwkSet(unvalidated)
        val types = subjectSyntaxTypes(unvalidated)
        val idTokenJWSAlg =
            parseRequiredSigningAlgorithm(unvalidated.idTokenSignedResponseAlg)
        val idTokenJWEAlg =
            parseRequiredEncryptionAlgorithm(unvalidated.idTokenEncryptedResponseAlg)
        val idTokenJWEEnc =
            parseRequiredEncryptionMethod(unvalidated.idTokenEncryptedResponseEnc)
        if ((
                !unvalidated.authorizationEncryptedResponseAlg.isNullOrEmpty() &&
                    unvalidated.authorizationEncryptedResponseEnc.isNullOrEmpty()
                ) ||
            (
                unvalidated.authorizationEncryptedResponseAlg.isNullOrEmpty() &&
                    !unvalidated.authorizationEncryptedResponseEnc.isNullOrEmpty()
                )
        ) {
            val msg = """Cannot construct ResponseSigningEncryptionSpec from client metadata:
                    property authorization_encrypted_response_alg exists 
                    but no property authorization_encrypted_response_enc found
            """.trimIndent()
            throw RuntimeException(msg)
        }

        val authSgnRespAlg = unvalidated.authorizationSignedResponseAlg?.let { signingAlgorithm(it) }
        val authEncRespAlg = unvalidated.authorizationEncryptedResponseAlg?.let { encryptionAlgorithm(it) }
        val authEncRespEnc = unvalidated.authorizationEncryptedResponseEnc?.let { encryptionMethod(it) }

        return ClientMetaData(
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

    private fun signingAlgorithm(signingAlg: String): JWSAlgorithm? {
        if (signingAlg.isEmpty()) {
            return null
        }
        val parsedSigningAlg = JWSAlgorithm.parse(signingAlg)
        if (!walletOpenId4VPConfig.authorizationSigningAlgValuesSupported.contains(parsedSigningAlg)) {
            error("The Signing algorithm $parsedSigningAlg specified in client metadata is not supported")
        }
        return parsedSigningAlg
    }

    private fun encryptionAlgorithm(encryptionAlg: String): JWEAlgorithm? {
        if (encryptionAlg.isEmpty()) {
            return null
        }
        val parsedEncryptionAlgorithm = JWEAlgorithm.parse(encryptionAlg)
        if (!walletOpenId4VPConfig.authorizationEncryptionAlgValuesSupported.contains(parsedEncryptionAlgorithm)) {
            error("The Encryption algorithm specified in received client metadata is not supported")
        }
        return parsedEncryptionAlgorithm
    }

    private fun encryptionMethod(encryptionMethod: String): EncryptionMethod? {
        if (encryptionMethod.isEmpty()) {
            return null
        }
        val parsedEncryptionMethodAlgorithm = EncryptionMethod.parse(encryptionMethod)
        if (!walletOpenId4VPConfig.authorizationEncryptionEncValuesSupported.contains(parsedEncryptionMethodAlgorithm)) {
            throw UnsupportedOperationException("The Encryption Encoding method specified in received client metadata is not supported")
        }
        return parsedEncryptionMethodAlgorithm
    }

    private fun parseRequiredSigningAlgorithm(signingAlg: String?): JWSAlgorithm =
        if (!signingAlg.isNullOrEmpty()) JWSAlgorithm.parse(signingAlg)
        else throw RequestValidationError.IdTokenSigningAlgMissing.asException()

    private fun parseRequiredEncryptionAlgorithm(encryptionAlg: String?): JWEAlgorithm =
        if (!encryptionAlg.isNullOrEmpty()) JWEAlgorithm.parse(encryptionAlg)
        else throw RequestValidationError.IdTokenEncryptionAlgMissing.asException()

    private fun parseRequiredEncryptionMethod(encryptionMethod: String?): EncryptionMethod =
        if (!encryptionMethod.isNullOrEmpty()) EncryptionMethod.parse(encryptionMethod)
        else throw RequestValidationError.IdTokenEncryptionMethodMissing.asException()

    private suspend fun jwkSet(clientMetadata: UnvalidatedClientMetaData): JWKSet {
        val atLeastOneJwkSourceDefined = !clientMetadata.jwks.isNullOrEmpty() || !clientMetadata.jwksUri.isNullOrEmpty()
        if (!atLeastOneJwkSourceDefined) {
            throw RequestValidationError.MissingClientMetadataJwksSource.asException()
        }

        val bothJwksSourcesDefined = !clientMetadata.jwks.isNullOrEmpty() && !clientMetadata.jwksUri.isNullOrEmpty()
        if (bothJwksSourcesDefined) {
            throw RequestValidationError.BothJwkUriAndInlineJwks.asException()
        }
        fun requiredJwks() = try {
            JWKSet.parse(clientMetadata.jwks?.toString())
        } catch (ex: ParseException) {
            throw ResolutionError.ClientMetadataJwkUriUnparsable(ex).asException()
        }

        suspend fun requiredJwksUri() = try {
            httpClientFactory().use { client ->
                val unparsed = client.get(URL(clientMetadata.jwksUri)).body<String>()
                JWKSet.parse(unparsed)
            }
        } catch (ex: IOException) {
            throw ResolutionError.ClientMetadataJwkResolutionFailed(ex).asException()
        } catch (ex: ParseException) {
            throw ResolutionError.ClientMetadataJwkResolutionFailed(ex).asException()
        }

        return when {
            clientMetadata.jwksUri.isNullOrEmpty() -> requiredJwks()
            else -> requiredJwksUri()
        }
    }

    private fun subjectSyntaxTypes(clientMetadata: UnvalidatedClientMetaData): List<SubjectSyntaxType> {
        val notEmpty = clientMetadata.subjectSyntaxTypesSupported.isNotEmpty()
        val allValidTypes = clientMetadata.subjectSyntaxTypesSupported.all(SubjectSyntaxType::isValid)
        fun asSubjectSyntaxType(s: String): SubjectSyntaxType = when {
            SubjectSyntaxType.JWKThumbprint.isValid(s) -> SubjectSyntaxType.JWKThumbprint
            else -> SubjectSyntaxType.DecentralizedIdentifier.parse(s)
        }
        return if (notEmpty && allValidTypes) clientMetadata.subjectSyntaxTypesSupported.map(::asSubjectSyntaxType)
        else throw RequestValidationError.SubjectSyntaxTypesWrongSyntax.asException()
    }
}
