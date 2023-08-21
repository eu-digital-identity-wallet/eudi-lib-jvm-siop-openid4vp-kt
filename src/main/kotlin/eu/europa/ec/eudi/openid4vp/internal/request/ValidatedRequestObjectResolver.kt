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

import eu.europa.ec.eudi.openid4vp.ClientMetaData
import eu.europa.ec.eudi.openid4vp.ResolvedRequestObject
import eu.europa.ec.eudi.openid4vp.WalletOpenId4VPConfig
import eu.europa.ec.eudi.openid4vp.internal.request.ValidatedRequestObject.*
import eu.europa.ec.eudi.openid4vp.internal.success
import eu.europa.ec.eudi.prex.PresentationDefinition

internal class ValidatedRequestObjectResolver(
    private val presentationDefinitionResolver: PresentationDefinitionResolver,
    private val clientMetaDataResolver: ClientMetaDataResolver,
) {

    suspend fun resolve(
        validated: ValidatedRequestObject,
        walletOpenId4VPConfig: WalletOpenId4VPConfig,
    ): Result<ResolvedRequestObject> = when (validated) {
        is SiopAuthentication -> resolveIdTokenRequest(validated)
        is OpenId4VPAuthorization -> resolveVpTokenRequest(validated, walletOpenId4VPConfig)
        is SiopOpenId4VPAuthentication -> resolveIdAndVpTokenRequest(validated, walletOpenId4VPConfig)
    }

    private suspend fun resolveIdAndVpTokenRequest(
        validated: SiopOpenId4VPAuthentication,
        walletOpenId4VPConfig: WalletOpenId4VPConfig,
    ): Result<ResolvedRequestObject> {
        val presentationDefinition =
            resolvePd(validated.presentationDefinitionSource, walletOpenId4VPConfig).getOrThrow()
        return ResolvedRequestObject.SiopOpenId4VPAuthentication(
            idTokenType = validated.idTokenType,
            presentationDefinition = presentationDefinition,
            clientMetaData = resolveClientMetaData(validated).getOrThrow(),
            clientId = validated.clientId,
            state = validated.state,
            scope = validated.scope,
            nonce = validated.nonce,
            responseMode = validated.responseMode,
        ).success()
    }

    private suspend fun resolveVpTokenRequest(
        validated: OpenId4VPAuthorization,
        walletOpenId4VPConfig: WalletOpenId4VPConfig,
    ): Result<ResolvedRequestObject> {
        val presentationDefinition =
            resolvePd(validated.presentationDefinitionSource, walletOpenId4VPConfig)
                .getOrThrow()
        return ResolvedRequestObject.OpenId4VPAuthorization(
            presentationDefinition = presentationDefinition,
            clientMetaData = resolveClientMetaData(validated).getOrThrow(),
            clientId = validated.clientId,
            state = validated.state,
            nonce = validated.nonce,
            responseMode = validated.responseMode,
        ).success()
    }

    private suspend fun resolveIdTokenRequest(validated: SiopAuthentication): Result<ResolvedRequestObject> =
        ResolvedRequestObject.SiopAuthentication(
            idTokenType = validated.idTokenType,
            clientMetaData = resolveClientMetaData(validated).getOrThrow(),
            clientId = validated.clientId,
            state = validated.state,
            scope = validated.scope,
            nonce = validated.nonce,
            responseMode = validated.responseMode,
        ).success()

    private suspend fun resolvePd(
        presentationDefinitionSource: PresentationDefinitionSource,
        walletOpenId4VPConfig: WalletOpenId4VPConfig,
    ): Result<PresentationDefinition> {
        return presentationDefinitionResolver.resolve(presentationDefinitionSource, walletOpenId4VPConfig)
    }

    private suspend fun resolveClientMetaData(validated: ValidatedRequestObject): Result<ClientMetaData> {
        return validated.clientMetaDataSource?.let {
            clientMetaDataResolver.resolve(it)
        } ?: error("Missing or invalid client metadata")
    }
}
