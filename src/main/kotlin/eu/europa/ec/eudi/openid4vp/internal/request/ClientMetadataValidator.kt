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
import eu.europa.ec.eudi.openid4vp.RequestValidationError.*
import eu.europa.ec.eudi.openid4vp.ResolutionError.ClientMetadataJwkResolutionFailed
import eu.europa.ec.eudi.openid4vp.ResolutionError.ClientMetadataJwkUriUnparsable
import eu.europa.ec.eudi.openid4vp.internal.requireOrThrow
import io.ktor.client.call.*
import io.ktor.client.request.*
import kotlinx.serialization.json.JsonObject
import java.io.IOException
import java.net.URL
import java.text.ParseException

internal class ClientMetadataValidator(
    private val walletOpenId4VPConfig: WalletOpenId4VPConfig,
    private val httpClientFactory: KtorHttpClientFactory = DefaultHttpClientFactory,
) {

    suspend fun validate(unvalidated: UnvalidatedClientMetaData): ClientMetaData {
        val jwkSets = jwkSet(unvalidated)
        val types = subjectSyntaxTypes(unvalidated.subjectSyntaxTypesSupported)
        val idTokenJWSAlg = unvalidated.idTokenSignedResponseAlg.signingAlg()
            ?: throw IdTokenSigningAlgMissing.asException()
        val idTokenJWEAlg = unvalidated.idTokenEncryptedResponseAlg.encAlg()
            ?: throw IdTokenEncryptionAlgMissing.asException()
        val idTokenJWEEnc = unvalidated.idTokenEncryptedResponseEnc.encMeth()
            ?: throw IdTokenEncryptionMethodMissing.asException()

        val authSgnRespAlg = authSgnRespAlg(unvalidated)
        val (authEncRespAlg, authEncRespEnc) = authEncRespAlgAndMethod(unvalidated)

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

    private fun authSgnRespAlg(unvalidated: UnvalidatedClientMetaData): JWSAlgorithm? =
        unvalidated.authorizationSignedResponseAlg?.signingAlg()?.also {
            requireOrThrow(walletOpenId4VPConfig.authorizationSigningAlgValuesSupported.contains(it)) {
                InvalidClientMetaData("The Signing algorithm ${it.name} is not supported").asException()
            }
        }

    private fun authEncRespAlgAndMethod(
        unvalidated: UnvalidatedClientMetaData,
    ): Pair<JWEAlgorithm?, EncryptionMethod?> {
        val authEncRespAlg = unvalidated.authorizationEncryptedResponseAlg?.encAlg()?.also {
            requireOrThrow(walletOpenId4VPConfig.authorizationEncryptionAlgValuesSupported.contains(it)) {
                InvalidClientMetaData("The Encryption algorithm ${it.name} is not supported").asException()
            }
        }

        val authEncRespEnc = unvalidated.authorizationEncryptedResponseEnc?.encMeth()?.also {
            requireOrThrow(walletOpenId4VPConfig.authorizationEncryptionEncValuesSupported.contains(it)) {
                InvalidClientMetaData("The Encryption Encoding method ${it.name} is not supported").asException()
            }
        }

        requireOrThrow(bothOrNone(authEncRespAlg, authEncRespEnc).invoke { it?.name.isNullOrEmpty() }) {
            InvalidClientMetaData(
                """
                Attributes authorization_encrypted_response_alg & authorization_encrypted_response_enc 
                should be either both provided or not provided.
                """.trimIndent(),
            ).asException()
        }
        return authEncRespAlg to authEncRespEnc
    }

    private suspend fun jwkSet(clientMetadata: UnvalidatedClientMetaData): JWKSet {
        val jwks = clientMetadata.jwks
        val jwksUri = clientMetadata.jwksUri

        fun JsonObject.asJWKSet(): JWKSet = try {
            JWKSet.parse(this.toString())
        } catch (ex: ParseException) {
            throw ClientMetadataJwkUriUnparsable(ex).asException()
        }

        suspend fun requiredJwksUri() = try {
            httpClientFactory().use { client ->
                val unparsed = client.get(URL(jwksUri)).body<String>()
                JWKSet.parse(unparsed)
            }
        } catch (ex: IOException) {
            throw ClientMetadataJwkResolutionFailed(ex).asException()
        } catch (ex: ParseException) {
            throw ClientMetadataJwkResolutionFailed(ex).asException()
        }
        return when (!jwks.isNullOrEmpty() to !jwksUri.isNullOrEmpty()) {
            false to false -> throw MissingClientMetadataJwksSource.asException()
            true to true -> throw BothJwkUriAndInlineJwks.asException()
            true to false -> checkNotNull(jwks).asJWKSet()
            else -> requiredJwksUri()
        }
    }
}

private fun String.signingAlg(): JWSAlgorithm? =
    JWSAlgorithm.parse(this).takeIf { JWSAlgorithm.Family.SIGNATURE.contains(it) }

private fun String.encAlg(): JWEAlgorithm? = JWEAlgorithm.parse(this)

private fun String.encMeth(): EncryptionMethod? = EncryptionMethod.parse(this)

private fun subjectSyntaxTypes(subjectSyntaxTypesSupported: List<String>): List<SubjectSyntaxType> {
    val notEmpty = subjectSyntaxTypesSupported.isNotEmpty()
    val allValidTypes = subjectSyntaxTypesSupported.all(SubjectSyntaxType::isValid)
    fun asSubjectSyntaxType(s: String): SubjectSyntaxType = when {
        SubjectSyntaxType.JWKThumbprint.isValid(s) -> SubjectSyntaxType.JWKThumbprint
        else -> SubjectSyntaxType.DecentralizedIdentifier.parse(s)
    }
    return if (notEmpty && allValidTypes) subjectSyntaxTypesSupported.map(::asSubjectSyntaxType)
    else throw SubjectSyntaxTypesWrongSyntax.asException()
}

private fun <T> bothOrNone(left: T, right: T): ((T) -> Boolean) -> Boolean = { test ->
    when (test(left) to test(right)) {
        true to true -> true
        false to false -> true
        else -> false
    }
}
