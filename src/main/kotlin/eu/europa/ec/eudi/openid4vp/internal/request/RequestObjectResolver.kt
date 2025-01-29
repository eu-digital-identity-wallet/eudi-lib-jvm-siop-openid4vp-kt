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
import eu.europa.ec.eudi.openid4vp.internal.base64UrlNoPadding
import eu.europa.ec.eudi.openid4vp.internal.jsonSupport
import eu.europa.ec.eudi.openid4vp.internal.request.ValidatedRequestObject.*
import io.ktor.client.*
import kotlinx.coroutines.coroutineScope
import kotlinx.io.bytestring.decodeToByteString
import kotlinx.io.bytestring.decodeToString
import kotlinx.serialization.*

internal class RequestObjectResolver(
    private val siopOpenId4VPConfig: SiopOpenId4VPConfig,
    httpClient: HttpClient,
) {
    private val presentationDefinitionResolver = PresentationDefinitionResolver(siopOpenId4VPConfig, httpClient)
    private val clientMetaDataValidator = ClientMetaDataValidator(httpClient)

    suspend fun resolveRequestObject(validated: ValidatedRequestObject): ResolvedRequestObject {
        val clientMetaData = resolveClientMetaData(validated)
        return when (validated) {
            is SiopAuthentication -> resolveIdTokenRequest(validated, clientMetaData)
            is OpenId4VPAuthorization -> resolveVpTokenRequest(validated, clientMetaData)
            is SiopOpenId4VPAuthentication -> resolveIdAndVpTokenRequest(validated, clientMetaData)
        }
    }

    private suspend fun resolveIdAndVpTokenRequest(
        request: SiopOpenId4VPAuthentication,
        clientMetaData: ValidatedClientMetaData?,
    ): ResolvedRequestObject = coroutineScope {
        val presentationQuery = query(request.querySource)
        val transactionData = request.transactionData?.let { resolveTransactionData(presentationQuery, it) }
        ResolvedRequestObject.SiopOpenId4VPAuthentication(
            client = request.client.toClient(),
            responseMode = request.responseMode,
            state = request.state,
            nonce = request.nonce,
            jarmRequirement = clientMetaData?.let { siopOpenId4VPConfig.jarmRequirement(it) },
            vpFormats = clientMetaData?.vpFormats ?: VpFormats.Empty,
            idTokenType = request.idTokenType,
            subjectSyntaxTypesSupported = clientMetaData?.subjectSyntaxTypesSupported.orEmpty(),
            scope = request.scope,
            presentationQuery = presentationQuery,
            transactionData = transactionData,
        )
    }

    private suspend fun resolveVpTokenRequest(
        authorization: OpenId4VPAuthorization,
        clientMetaData: ValidatedClientMetaData?,
    ): ResolvedRequestObject {
        val presentationQuery = query(authorization.querySource)
        val transactionData = authorization.transactionData?.let { resolveTransactionData(presentationQuery, it) }
        return ResolvedRequestObject.OpenId4VPAuthorization(
            client = authorization.client.toClient(),
            responseMode = authorization.responseMode,
            state = authorization.state,
            nonce = authorization.nonce,
            jarmRequirement = clientMetaData?.let { siopOpenId4VPConfig.jarmRequirement(it) },
            vpFormats = clientMetaData?.vpFormats ?: VpFormats.Empty,
            presentationQuery = presentationQuery,
            transactionData = transactionData,
        )
    }

    private fun resolveIdTokenRequest(
        authentication: SiopAuthentication,
        clientMetaData: ValidatedClientMetaData?,
    ): ResolvedRequestObject {
        return ResolvedRequestObject.SiopAuthentication(
            client = authentication.client.toClient(),
            responseMode = authentication.responseMode,
            state = authentication.state,
            nonce = authentication.nonce,
            jarmRequirement = clientMetaData?.let { siopOpenId4VPConfig.jarmRequirement(it) },
            idTokenType = authentication.idTokenType,
            subjectSyntaxTypesSupported = clientMetaData?.subjectSyntaxTypesSupported.orEmpty(),
            scope = authentication.scope,
        )
    }

    private suspend fun query(
        querySource: QuerySource,
    ) = when (querySource) {
        is QuerySource.ByPresentationDefinitionSource ->
            PresentationQuery.ByPresentationDefinition(
                presentationDefinitionResolver.resolvePresentationDefinition(
                    querySource.value,
                ),
            )

        is QuerySource.ByDCQLQuery -> PresentationQuery.ByDigitalCredentialsQuery(
            querySource.value,
        )

        is QuerySource.ByScope -> lookupKnownPresentationDefinitionsOrDCQLQueries(
            querySource.value,
        )
    }

    private fun lookupKnownPresentationDefinitionsOrDCQLQueries(scope: Scope): PresentationQuery {
        scope.items().forEach { item ->
            siopOpenId4VPConfig.vpConfiguration.knownPresentationDefinitionsPerScope[item.value]
                ?.let { return PresentationQuery.ByPresentationDefinition(it) }
        }
        scope.items().forEach { item ->
            siopOpenId4VPConfig.vpConfiguration.knownDCQLQueriesPerScope[item.value]
                ?.let { return PresentationQuery.ByDigitalCredentialsQuery(it) }
        }
        throw ResolutionError.UnknownScope(scope).asException()
    }

    private suspend fun resolveClientMetaData(validated: ValidatedRequestObject): ValidatedClientMetaData? =
        validated.clientMetaData?.let { unvalidated ->
            clientMetaDataValidator.validateClientMetaData(unvalidated, validated.responseMode)
        }

    private fun resolveTransactionData(query: PresentationQuery, unresolvedTransactionData: List<String>): List<ResolvedTransactionData> {
        fun resolveTransactionDataCredentialIds(unresolved: List<String>): List<TransactionDataCredentialId> =
            when (query) {
                is PresentationQuery.ByPresentationDefinition -> {
                    val inputDescriptorIds = query.value.inputDescriptors.map { it.id }
                    unresolved.map {
                        val match = inputDescriptorIds.firstOrNull { inputDescriptorId -> inputDescriptorId.value == it }
                        requireNotNull(match) {
                            "Invalid '${OpenId4VPSpec.TRANSACTION_DATA_CREDENTIAL_IDS}': '$unresolved'"
                        }
                        TransactionDataCredentialId.PresentationExchange(match)
                    }
                }
                is PresentationQuery.ByDigitalCredentialsQuery -> {
                    val queryIds = query.value.credentials.map { it.id }
                    unresolved.map {
                        val match = queryIds.firstOrNull { queryId -> queryId.value == it }
                        requireNotNull(match) {
                            "Invalid '${OpenId4VPSpec.TRANSACTION_DATA_CREDENTIAL_IDS}': '$unresolved'"
                        }
                        TransactionDataCredentialId.DCQL(match)
                    }
                }
            }

        return runCatching {
            val walletSupportedTransactionDataTypes = siopOpenId4VPConfig.supportedTransactionDataTypes.associateBy { it.type }

            unresolvedTransactionData.map { encoded ->
                val decoded = base64UrlNoPadding.decodeToByteString(encoded)
                val serialized = decoded.decodeToString()
                val deserialized = jsonSupport.decodeFromString<BaseTransactionData>(serialized)

                val walletSupportedTransactionDataType = walletSupportedTransactionDataTypes[deserialized.type]
                require(walletSupportedTransactionDataType != null) {
                    "Unsupported '${OpenId4VPSpec.TRANSACTION_DATA_TYPE}': '${deserialized.type}'"
                }

                val transactionDataCredentialIds = resolveTransactionDataCredentialIds(deserialized.credentialIds)

                val verifierSupportedHashAlgorithms = deserialized.hashAlgorithms ?: setOf(HashAlgorithm.SHA_256)
                val commonHashAlgorithms = walletSupportedTransactionDataType.hashAlgorithms.intersect(verifierSupportedHashAlgorithms)
                require(commonHashAlgorithms.isNotEmpty()) {
                    "Unsupported '${OpenId4VPSpec.TRANSACTION_DATA_HASH_ALGORITHMS}': '$verifierSupportedHashAlgorithms'"
                }

                ResolvedTransactionData(
                    type = deserialized.type,
                    credentialIds = transactionDataCredentialIds,
                    hashAlgorithms = commonHashAlgorithms,
                    value = encoded,
                )
            }
        }.getOrElse { error -> throw ResolutionError.InvalidTransactionData(error).asException() }
    }
}

private fun AuthenticatedClient.toClient(): Client =
    when (this) {
        is AuthenticatedClient.Preregistered -> Client.Preregistered(
            preregisteredClient.clientId,
            preregisteredClient.legalName,
        )

        is AuthenticatedClient.RedirectUri -> Client.RedirectUri(clientId)
        is AuthenticatedClient.X509SanDns -> Client.X509SanDns(clientId, chain[0])
        is AuthenticatedClient.X509SanUri -> Client.X509SanUri(clientId, chain[0])
        is AuthenticatedClient.DIDClient -> Client.DIDClient(client.uri)
        is AuthenticatedClient.Attested -> Client.Attested(clientId)
    }

@Serializable
private data class BaseTransactionData(

    @SerialName(OpenId4VPSpec.TRANSACTION_DATA_TYPE)
    @Required
    val type: TransactionDataType,

    @SerialName(OpenId4VPSpec.TRANSACTION_DATA_CREDENTIAL_IDS)
    @Required
    val credentialIds: List<String>,

    @SerialName(OpenId4VPSpec.TRANSACTION_DATA_HASH_ALGORITHMS)
    val hashAlgorithms: Set<HashAlgorithm>? = null,

) {
    init {
        require(credentialIds.isNotEmpty()) { "'${OpenId4VPSpec.TRANSACTION_DATA_CREDENTIAL_IDS}' must not be empty" }
    }
}
