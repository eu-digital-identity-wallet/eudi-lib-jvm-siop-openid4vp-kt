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

import eu.europa.ec.eudi.openid4vp.ResolvedRequestObject
import eu.europa.ec.eudi.openid4vp.SiopOpenId4VPConfig
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
        clientMetaData: ValidatedClientMetaData,
    ): ResolvedRequestObject = coroutineScope {
        val presentationDefinition = presentationDefinition(request.presentationDefinitionSource)
        ResolvedRequestObject.SiopOpenId4VPAuthentication(
            clientId = request.clientId,
            responseMode = request.responseMode,
            state = request.state,
            nonce = request.nonce,
            jarmRequirement = siopOpenId4VPConfig.jarmRequirement(clientMetaData),
            idTokenType = request.idTokenType,
            subjectSyntaxTypesSupported = clientMetaData.subjectSyntaxTypesSupported,
            scope = request.scope,
            presentationDefinition = presentationDefinition,
        )
    }

    private suspend fun resolveVpTokenRequest(
        authorization: OpenId4VPAuthorization,
        clientMetaData: ValidatedClientMetaData,
    ): ResolvedRequestObject {
        val presentationDefinition = presentationDefinition(authorization.presentationDefinitionSource)
        return ResolvedRequestObject.OpenId4VPAuthorization(
            clientId = authorization.clientId,
            responseMode = authorization.responseMode,
            state = authorization.state,
            nonce = authorization.nonce,
            jarmRequirement = siopOpenId4VPConfig.jarmRequirement(clientMetaData),
            presentationDefinition = presentationDefinition,
        )
    }

    private fun resolveIdTokenRequest(
        authentication: SiopAuthentication,
        clientMetaData: ValidatedClientMetaData,
    ): ResolvedRequestObject {
        return ResolvedRequestObject.SiopAuthentication(
            clientId = authentication.clientId,
            responseMode = authentication.responseMode,
            state = authentication.state,
            nonce = authentication.nonce,
            jarmRequirement = siopOpenId4VPConfig.jarmRequirement(clientMetaData),
            idTokenType = authentication.idTokenType,
            subjectSyntaxTypesSupported = clientMetaData.subjectSyntaxTypesSupported,
            scope = authentication.scope,
        )
    }

    private suspend fun presentationDefinition(
        presentationDefinitionSource: PresentationDefinitionSource,
    ) = presentationDefinitionResolver.resolvePresentationDefinition(presentationDefinitionSource)

    private suspend fun resolveClientMetaData(validated: ValidatedRequestObject): ValidatedClientMetaData {
        val source = checkNotNull(validated.clientMetaDataSource) { "Missing or invalid client metadata" }
        return clientMetaDataValidator.validateClientMetaData(source, validated.responseMode)
    }
}
