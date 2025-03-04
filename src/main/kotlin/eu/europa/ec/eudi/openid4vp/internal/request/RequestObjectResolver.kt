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
import eu.europa.ec.eudi.openid4vp.internal.request.ValidatedRequestObject.*
import io.ktor.client.*
import kotlinx.coroutines.coroutineScope

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
        val vpFormatsCommonGround = clientMetaData?.let { resolveVpFormatsCommonGround(it.vpFormats) }
        ResolvedRequestObject.SiopOpenId4VPAuthentication(
            client = request.client.toClient(),
            responseMode = request.responseMode,
            state = request.state,
            nonce = request.nonce,
            jarmRequirement = clientMetaData?.let { siopOpenId4VPConfig.jarmRequirement(it) },
            vpFormats = vpFormatsCommonGround,
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
        val vpFormatsCommonGround = clientMetaData?.let { resolveVpFormatsCommonGround(it.vpFormats) }
        return ResolvedRequestObject.OpenId4VPAuthorization(
            client = authorization.client.toClient(),
            responseMode = authorization.responseMode,
            state = authorization.state,
            nonce = authorization.nonce,
            jarmRequirement = clientMetaData?.let { siopOpenId4VPConfig.jarmRequirement(it) },
            vpFormats = vpFormatsCommonGround,
            presentationQuery = presentationQuery,
            transactionData = transactionData,
        )
    }

    private fun resolveVpFormatsCommonGround(clientVpFormats: VpFormats): VpFormats {
        val walletSupportedVpFormats = siopOpenId4VPConfig.vpConfiguration.vpFormats
        val scg = (walletSupportedVpFormats.sdJwtVc to clientVpFormats.sdJwtVc).commonGround()
        val mcg = (walletSupportedVpFormats.msoMdoc to clientVpFormats.msoMdoc).commonGround()
        return if (scg != null || mcg != null)
            VpFormats(scg, mcg)
        else
            throw ResolutionError.ClientVpFormatsNotSupportedFromWallet.asException()
    }

    private fun Pair<VpFormat.SdJwtVc?, VpFormat.SdJwtVc?>.commonGround(): VpFormat.SdJwtVc? {
        val kbJwtAlgs = first?.kbJwtAlgorithms?.intersect((second?.kbJwtAlgorithms?.toSet() ?: emptySet()).toSet())
        val sdJwtAlgs = first?.sdJwtAlgorithms?.intersect((second?.sdJwtAlgorithms?.toSet() ?: emptySet()).toSet())
        return if (!kbJwtAlgs.isNullOrEmpty() && !sdJwtAlgs.isNullOrEmpty()) {
            VpFormat.SdJwtVc(sdJwtAlgs.toList(), kbJwtAlgs.toList())
        } else
            null
    }

    private fun Pair<VpFormat.MsoMdoc?, VpFormat.MsoMdoc?>.commonGround(): VpFormat.MsoMdoc? {
        val algs = first?.algorithms?.intersect((second?.algorithms?.toSet() ?: emptySet()).toSet())
        return if (!algs.isNullOrEmpty()) {
            VpFormat.MsoMdoc(algs.toList())
        } else
            null
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

    private fun resolveTransactionData(query: PresentationQuery, unresolvedTransactionData: List<String>): List<TransactionData> =
        runCatching {
            unresolvedTransactionData.map { unresolved ->
                TransactionData(unresolved, siopOpenId4VPConfig.vpConfiguration.supportedTransactionDataTypes, query).getOrThrow()
            }
        }.getOrElse { error -> throw ResolutionError.InvalidTransactionData(error).asException() }
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
