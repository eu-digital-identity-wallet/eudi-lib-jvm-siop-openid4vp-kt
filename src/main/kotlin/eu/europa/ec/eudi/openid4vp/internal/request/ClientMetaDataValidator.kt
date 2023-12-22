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
import eu.europa.ec.eudi.openid4vp.RequestValidationError.InvalidClientMetaData
import eu.europa.ec.eudi.openid4vp.internal.requireOrThrow
import io.ktor.client.*
import io.ktor.client.call.*
import io.ktor.client.request.*
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.JsonObject
import java.io.IOException
import java.net.URL
import java.text.ParseException

/**
 * Extracts the client meta-data and validates them
 */
internal class ClientMetadataValidator(
    private val httpClientFactory: KtorHttpClientFactory,
) {

    /**
     * Gets the meta-data from the [clientMetaDataSource] and then validates them
     * @param clientMetaDataSource the source to obtain the meta-data
     * @param responseMode the response mode under which the meta-data should be validated
     * @throws AuthorizationRequestException in case of a problem
     */
    @Throws(AuthorizationRequestException::class)
    suspend fun validate(clientMetaDataSource: ClientMetaDataSource, responseMode: ResponseMode): ClientMetaData {
        val unvalidatedClientMetaData = when (clientMetaDataSource) {
            is ClientMetaDataSource.ByValue -> clientMetaDataSource.metaData
            is ClientMetaDataSource.ByReference -> fetch(clientMetaDataSource.url)
        }
        return validate(unvalidatedClientMetaData, responseMode)
    }

    @Throws(AuthorizationRequestException::class)
    suspend fun validate(unvalidated: UnvalidatedClientMetaData, responseMode: ResponseMode): ClientMetaData {
        val types = subjectSyntaxTypes(unvalidated.subjectSyntaxTypesSupported)
        val authSgnRespAlg = authSgnRespAlg(unvalidated, responseMode)
        val (authEncRespAlg, authEncRespEnc) = authEncRespAlgAndMethod(unvalidated, responseMode)
        val requiresEncryption = responseMode.isJarm() && null != authEncRespAlg && authEncRespEnc != null
        val jwkSets = if (requiresEncryption) jwkSet(unvalidated) else null
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

    private fun authSgnRespAlg(unvalidated: UnvalidatedClientMetaData, responseMode: ResponseMode): JWSAlgorithm? {
        val unvalidatedAlg = unvalidated.authorizationSignedResponseAlg
        return if (!responseMode.isJarm() || unvalidatedAlg.isNullOrEmpty()) null
        else unvalidatedAlg.signingAlg()
            ?: throw InvalidClientMetaData("Invalid signing algorithm $unvalidatedAlg").asException()
    }

    private fun authEncRespAlgAndMethod(
        unvalidated: UnvalidatedClientMetaData,
        responseMode: ResponseMode,
    ): Pair<JWEAlgorithm?, EncryptionMethod?> {
        if (!responseMode.isJarm()) return null to null

        val authEncRespAlg = unvalidated.authorizationEncryptedResponseAlg?.let { alg ->
            alg.encAlg() ?: throw InvalidClientMetaData("Invalid encryption algorithm $alg").asException()
        }

        val authEncRespEnc = unvalidated.authorizationEncryptedResponseEnc?.let { encMeth ->
            encMeth.encMeth() ?: throw InvalidClientMetaData("Invalid encryption method $encMeth").asException()
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

    private suspend fun jwkSet(clientMetadata: UnvalidatedClientMetaData): JWKSet {
        val jwks = clientMetadata.jwks
        val jwksUri = clientMetadata.jwksUri

        fun JsonObject.asJWKSet(): JWKSet = try {
            JWKSet.parse(this.toString())
        } catch (ex: ParseException) {
            throw ResolutionError.ClientMetadataJwkUriUnparsable(ex).asException()
        }

        suspend fun requiredJwksUri() = httpClientFactory().use { client ->
            try {
                val unparsed = client.get(URL(jwksUri)).body<String>()
                JWKSet.parse(unparsed)
            } catch (ex: IOException) {
                throw ResolutionError.ClientMetadataJwkResolutionFailed(ex).asException()
            } catch (ex: ParseException) {
                throw ResolutionError.ClientMetadataJwkResolutionFailed(ex).asException()
            }
        }

        return when (!jwks.isNullOrEmpty() to !jwksUri.isNullOrEmpty()) {
            false to false -> throw RequestValidationError.MissingClientMetadataJwksSource.asException()
            true to true -> throw RequestValidationError.BothJwkUriAndInlineJwks.asException()
            true to false -> checkNotNull(jwks).asJWKSet()
            else -> requiredJwksUri()
        }
    }

    @Throws(AuthorizationRequestException::class)
    private suspend fun fetch(url: URL): UnvalidatedClientMetaData = httpClientFactory().use { client ->
        try {
            client.get(url).body<UnvalidatedClientMetaData>()
        } catch (t: Throwable) {
            throw ResolutionError.UnableToFetchClientMetadata(t).asException()
        }
    }
}

@Serializable
internal data class UnvalidatedClientMetaData(
    @SerialName("jwks_uri") val jwksUri: String? = null,
    @SerialName("jwks") val jwks: JsonObject? = null,
    @SerialName("subject_syntax_types_supported") val subjectSyntaxTypesSupported: List<String>? = emptyList(),
    @SerialName("authorization_signed_response_alg") val authorizationSignedResponseAlg: String? = null,
    @SerialName("authorization_encrypted_response_alg") val authorizationEncryptedResponseAlg: String? = null,
    @SerialName("authorization_encrypted_response_enc") val authorizationEncryptedResponseEnc: String? = null,
)

private fun String.signingAlg(): JWSAlgorithm? =
    JWSAlgorithm.parse(this).takeIf { JWSAlgorithm.Family.SIGNATURE.contains(it) }

private fun String.encAlg(): JWEAlgorithm? = JWEAlgorithm.parse(this)

private fun String.encMeth(): EncryptionMethod? = EncryptionMethod.parse(this)

private fun subjectSyntaxTypes(subjectSyntaxTypesSupported: List<String>?): List<SubjectSyntaxType>? {
    fun String.asSubjectSyntaxType(): SubjectSyntaxType = when {
        !SubjectSyntaxType.isValid(this) -> throw RequestValidationError.SubjectSyntaxTypesWrongSyntax.asException()
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
