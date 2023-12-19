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

import eu.europa.ec.eudi.openid4vp.*
import io.ktor.client.*
import io.ktor.client.call.*
import io.ktor.client.request.*
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.JsonObject
import java.net.URL

/**
 * Extracts the client meta-data and validates them
 */
internal class ClientMetaDataResolver(
    private val httpClientFactory: KtorHttpClientFactory,
    walletOpenId4VPConfig: WalletOpenId4VPConfig,
) {
    private val clientMetadataValidator = ClientMetadataValidator(walletOpenId4VPConfig, httpClientFactory)

    /**
     * Gets the meta-data from the [clientMetaDataSource] and then validates them
     * @param clientMetaDataSource the source to obtain the meta-data
     * @throws AuthorizationRequestException in case of a problem
     */
    @Throws(AuthorizationRequestException::class)
    suspend fun resolve(clientMetaDataSource: ClientMetaDataSource): ClientMetaData {
        val unvalidatedClientMetaData = when (clientMetaDataSource) {
            is ClientMetaDataSource.ByValue -> clientMetaDataSource.metaData
            is ClientMetaDataSource.ByReference -> fetch(clientMetaDataSource.url)
        }
        return clientMetadataValidator.validate(unvalidatedClientMetaData)
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
) : java.io.Serializable
