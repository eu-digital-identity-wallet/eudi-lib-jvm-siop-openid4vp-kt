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
import com.nimbusds.jose.jwk.ThumbprintURI
import eu.europa.ec.eudi.openid4vp.*
import eu.europa.ec.eudi.openid4vp.ResolutionError.ClientMetadataJwkResolutionFailed
import eu.europa.ec.eudi.openid4vp.ResolutionError.UnableToFetchClientMetadata
import eu.europa.ec.eudi.openid4vp.internal.ensure
import io.ktor.client.*
import io.ktor.client.call.*
import io.ktor.client.request.*
import kotlinx.serialization.SerializationException
import kotlinx.serialization.json.JsonObject
import java.io.IOException
import java.net.URL
import java.text.ParseException

internal class ClientMetaDataValidator(private val httpClient: HttpClient) {

    /**
     * Gets the meta-data from the [clientMetaDataSource] and then validates them
     * @param clientMetaDataSource the source to obtain the meta-data
     * @param responseMode the response mode under which the meta-data should be validated
     * @throws AuthorizationRequestException in case of a problem
     */
    @Throws(AuthorizationRequestException::class)
    suspend fun validateClientMetaData(
        clientMetaDataSource: ClientMetaDataSource,
        responseMode: ResponseMode,
    ): ValidatedClientMetaData {
        val unvalidatedClientMetaData = resolveClientMetaData(clientMetaDataSource)
        return validate(unvalidatedClientMetaData, responseMode)
    }

    private suspend fun resolveClientMetaData(clientMetaDataSource: ClientMetaDataSource): UnvalidatedClientMetaData =
        when (clientMetaDataSource) {
            is ClientMetaDataSource.ByValue -> clientMetaDataSource.metaData
            is ClientMetaDataSource.ByReference -> try {
                httpClient.get(clientMetaDataSource.url).body<UnvalidatedClientMetaData>()
            } catch (t: IOException) {
                throw UnableToFetchClientMetadata(t).asException()
            } catch (t: SerializationException) {
                throw UnableToFetchClientMetadata(t).asException()
            }
        }

    @Throws(AuthorizationRequestException::class)
    internal suspend fun validate(
        unvalidated: UnvalidatedClientMetaData,
        responseMode: ResponseMode,
    ): ValidatedClientMetaData {
        val types = subjectSyntaxTypes(unvalidated.subjectSyntaxTypesSupported)
        val authSgnRespAlg = authSgnRespAlg(unvalidated, responseMode)
        val (authEncRespAlg, authEncRespEnc) = authEncRespAlgAndMethod(unvalidated, responseMode)
        val requiresEncryption = responseMode.isJarm() && null != authEncRespAlg && authEncRespEnc != null
        val jwkSets = if (requiresEncryption) jwkSet(unvalidated) else null
        ensure(!responseMode.isJarm() || !(authSgnRespAlg == null && authEncRespAlg == null && authEncRespEnc == null)) {
            RequestValidationError.InvalidClientMetaData("None of the JARM related metadata provided").asException()
        }

        return ValidatedClientMetaData(
            jwkSet = jwkSets,
            subjectSyntaxTypesSupported = types,
            authorizationSignedResponseAlg = authSgnRespAlg,
            authorizationEncryptedResponseAlg = authEncRespAlg,
            authorizationEncryptedResponseEnc = authEncRespEnc,
        )
    }

    private suspend fun jwkSet(clientMetadata: UnvalidatedClientMetaData): JWKSet {
        val jwks = clientMetadata.jwks
        val jwksUri = clientMetadata.jwksUri

        fun JsonObject.asJWKSet(): JWKSet = try {
            JWKSet.parse(this.toString())
        } catch (ex: ParseException) {
            throw ResolutionError.ClientMetadataJwkUriUnparsable(ex).asException()
        }

        suspend fun requiredJwksUri() = try {
            val unparsed = httpClient.get(URL(jwksUri)).body<String>()
            JWKSet.parse(unparsed)
        } catch (ex: IOException) {
            throw ClientMetadataJwkResolutionFailed(ex).asException()
        } catch (ex: ParseException) {
            throw ClientMetadataJwkResolutionFailed(ex).asException()
        }

        return when (!jwks.isNullOrEmpty() to !jwksUri.isNullOrEmpty()) {
            false to false -> throw RequestValidationError.MissingClientMetadataJwksSource.asException()
            true to true -> throw RequestValidationError.BothJwkUriAndInlineJwks.asException()
            true to false -> checkNotNull(jwks).asJWKSet()
            else -> requiredJwksUri()
        }
    }
}

private fun ResponseMode.isJarm() = when (this) {
    is ResponseMode.DirectPost -> false
    is ResponseMode.DirectPostJwt -> true
    is ResponseMode.Fragment -> false
    is ResponseMode.FragmentJwt -> true
    is ResponseMode.Query -> false
    is ResponseMode.QueryJwt -> true
}

private fun authSgnRespAlg(unvalidated: UnvalidatedClientMetaData, responseMode: ResponseMode): JWSAlgorithm? {
    val unvalidatedAlg = unvalidated.authorizationSignedResponseAlg
    return if (!responseMode.isJarm() || unvalidatedAlg.isNullOrEmpty()) null
    else unvalidatedAlg.signingAlg()
        ?: throw RequestValidationError.InvalidClientMetaData("Invalid signing algorithm $unvalidatedAlg").asException()
}

private fun String.signingAlg(): JWSAlgorithm? =
    JWSAlgorithm.parse(this).takeIf { JWSAlgorithm.Family.SIGNATURE.contains(it) }

private fun String.encAlg(): JWEAlgorithm? = JWEAlgorithm.parse(this)

private fun String.encMeth(): EncryptionMethod? = EncryptionMethod.parse(this)
private fun authEncRespAlgAndMethod(
    unvalidated: UnvalidatedClientMetaData,
    responseMode: ResponseMode,
): Pair<JWEAlgorithm?, EncryptionMethod?> {
    if (!responseMode.isJarm()) return null to null

    val authEncRespAlg = unvalidated.authorizationEncryptedResponseAlg?.let { alg ->
        alg.encAlg() ?: throw RequestValidationError.InvalidClientMetaData("Invalid encryption algorithm $alg")
            .asException()
    }

    val authEncRespEnc = unvalidated.authorizationEncryptedResponseEnc?.let { encMeth ->
        encMeth.encMeth() ?: throw RequestValidationError.InvalidClientMetaData("Invalid encryption method $encMeth")
            .asException()
    }

    ensure(bothOrNone(authEncRespAlg, authEncRespEnc).invoke { it?.name.isNullOrEmpty() }) {
        RequestValidationError.InvalidClientMetaData(
            """
                Attributes authorization_encrypted_response_alg & authorization_encrypted_response_enc 
                should be either both provided or not provided to support JARM.
            """.trimIndent(),
        ).asException()
    }
    return authEncRespAlg to authEncRespEnc
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

private fun <T> bothOrNone(left: T, right: T): ((T) -> Boolean) -> Boolean = { test ->
    when (test(left) to test(right)) {
        true to true -> true
        false to false -> true
        else -> false
    }
}
