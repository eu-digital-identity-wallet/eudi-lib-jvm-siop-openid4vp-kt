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
    private val httpClientFactory: KtorHttpClientFactory,
) {

    suspend fun validate(unvalidated: UnvalidatedClientMetaData, responseMode: ResponseMode): ClientMetaData {
        val jwkSets = jwkSet(unvalidated, responseMode)
        val types = subjectSyntaxTypes(unvalidated.subjectSyntaxTypesSupported)
        val authSgnRespAlg = authSgnRespAlg(unvalidated)
        val (authEncRespAlg, authEncRespEnc) = authEncRespAlgAndMethod(unvalidated, responseMode)

        requireOrThrow(!responseMode.isJarm() || !(authSgnRespAlg == null && authEncRespAlg == null && authEncRespEnc == null)) {
            InvalidClientMetaData("None of the JARM related metadata provided").asException()
        }

        return ClientMetaData(
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
        responseMode: ResponseMode,
    ): Pair<JWEAlgorithm?, EncryptionMethod?> {
        if (!responseMode.isJarm()) return null to null

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
                should be either both provided or not provided to support JARM.
                """.trimIndent(),
            ).asException()
        }
        return authEncRespAlg to authEncRespEnc
    }

    private fun ResponseMode.isJarm() = when (this) {
        is ResponseMode.DirectPost -> false
        is ResponseMode.DirectPostJwt -> true
        is ResponseMode.Fragment -> false
        is ResponseMode.FragmentJwt -> true
        is ResponseMode.Query -> false
        is ResponseMode.QueryJwt -> true
    }

    private suspend fun jwkSet(clientMetadata: UnvalidatedClientMetaData, responseMode: ResponseMode): JWKSet? {
        return if (!responseMode.isJarm()) null
        else {
            val jwks = clientMetadata.jwks
            val jwksUri = clientMetadata.jwksUri

            fun JsonObject.asJWKSet(): JWKSet = try {
                JWKSet.parse(this.toString())
            } catch (ex: ParseException) {
                throw ClientMetadataJwkUriUnparsable(ex).asException()
            }

            suspend fun requiredJwksUri() = httpClientFactory().use { client ->
                try {
                    val unparsed = client.get(URL(jwksUri)).body<String>()
                    JWKSet.parse(unparsed)
                } catch (ex: IOException) {
                    throw ClientMetadataJwkResolutionFailed(ex).asException()
                } catch (ex: ParseException) {
                    throw ClientMetadataJwkResolutionFailed(ex).asException()
                }
            }

            when (!jwks.isNullOrEmpty() to !jwksUri.isNullOrEmpty()) {
                false to false -> throw MissingClientMetadataJwksSource.asException()
                true to true -> throw BothJwkUriAndInlineJwks.asException()
                true to false -> checkNotNull(jwks).asJWKSet()
                else -> requiredJwksUri()
            }
        }
    }
}

private fun String.signingAlg(): JWSAlgorithm? =
    JWSAlgorithm.parse(this).takeIf { JWSAlgorithm.Family.SIGNATURE.contains(it) }

private fun String.encAlg(): JWEAlgorithm? = JWEAlgorithm.parse(this)

private fun String.encMeth(): EncryptionMethod? = EncryptionMethod.parse(this)

private fun subjectSyntaxTypes(subjectSyntaxTypesSupported: List<String>?): List<SubjectSyntaxType>? {
    fun String.asSubjectSyntaxType(): SubjectSyntaxType = when {
        !SubjectSyntaxType.isValid(this) -> throw SubjectSyntaxTypesWrongSyntax.asException()
        SubjectSyntaxType.JWKThumbprint.isValid(this) -> SubjectSyntaxType.JWKThumbprint
        else -> SubjectSyntaxType.DecentralizedIdentifier.parse(this)
    }
    return subjectSyntaxTypesSupported?.map { it.asSubjectSyntaxType() }
}

private fun <T> bothOrNone(left: T, right: T): ((T) -> Boolean) -> Boolean = { test ->
    when (test(left) to test(right)) {
        true to true -> true
        false to false -> true
        else -> false
    }
}
