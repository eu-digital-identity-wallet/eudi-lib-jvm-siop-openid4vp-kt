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

import eu.europa.ec.eudi.openid4vp.KtorHttpClientFactory
import eu.europa.ec.eudi.openid4vp.ResolvedRequestObject
import eu.europa.ec.eudi.openid4vp.SiopOpenId4VPConfig
import eu.europa.ec.eudi.openid4vp.internal.request.ValidatedRequestObject.*
import eu.europa.ec.eudi.prex.PresentationDefinition

internal class RequestObjectResolver private constructor(
    private val siopOpenId4VPConfig: SiopOpenId4VPConfig,
    private val presentationDefinitionResolver: PresentationDefinitionResolver,
    private val clientMetadataValidator: ClientMetaDataValidator,
) {

    constructor(
        siopOpenId4VPConfig: SiopOpenId4VPConfig,
        httpClientFactory: KtorHttpClientFactory,
    ) : this(
        siopOpenId4VPConfig,
        PresentationDefinitionResolver(httpClientFactory),
        ClientMetaDataValidator(httpClientFactory),
    )

    suspend fun resolve(
        validated: ValidatedRequestObject,
    ): ResolvedRequestObject {
        val clientMetaData = resolveClientMetaData(validated)
        return with(siopOpenId4VPConfig) {
            when (validated) {
                is SiopAuthentication -> resolveIdTokenRequest(validated, clientMetaData)
                is OpenId4VPAuthorization -> resolveVpTokenRequest(validated, clientMetaData)
                is SiopOpenId4VPAuthentication -> resolveIdAndVpTokenRequest(validated, clientMetaData)
            }
        }
    }

    private suspend fun SiopOpenId4VPConfig.resolveIdAndVpTokenRequest(
        request: SiopOpenId4VPAuthentication,
        clientMetaData: ValidatedClientMetaData,
    ): ResolvedRequestObject {
        val presentationDefinition = presentationDefinition(request.presentationDefinitionSource)
        return ResolvedRequestObject.SiopOpenId4VPAuthentication(
            clientId = request.clientId,
            responseMode = request.responseMode,
            state = request.state,
            nonce = request.nonce,
            jarmRequirement = jarmRequirement(clientMetaData),
            idTokenType = request.idTokenType,
            subjectSyntaxTypesSupported = clientMetaData.subjectSyntaxTypesSupported,
            scope = request.scope,
            presentationDefinition = presentationDefinition,
        )
    }

    private suspend fun SiopOpenId4VPConfig.resolveVpTokenRequest(
        authorization: OpenId4VPAuthorization,
        clientMetaData: ValidatedClientMetaData,
    ): ResolvedRequestObject {
        val presentationDefinition = presentationDefinition(authorization.presentationDefinitionSource)
        return ResolvedRequestObject.OpenId4VPAuthorization(
            clientId = authorization.clientId,
            responseMode = authorization.responseMode,
            state = authorization.state,
            nonce = authorization.nonce,
            jarmRequirement = jarmRequirement(clientMetaData),
            presentationDefinition = presentationDefinition,
        )
    }

    private fun SiopOpenId4VPConfig.resolveIdTokenRequest(
        authentication: SiopAuthentication,
        clientMetaData: ValidatedClientMetaData,
    ): ResolvedRequestObject {
        return ResolvedRequestObject.SiopAuthentication(
            clientId = authentication.clientId,
            responseMode = authentication.responseMode,
            state = authentication.state,
            nonce = authentication.nonce,
            jarmRequirement = jarmRequirement(clientMetaData),
            idTokenType = authentication.idTokenType,
            subjectSyntaxTypesSupported = clientMetaData.subjectSyntaxTypesSupported,
            scope = authentication.scope,
        )
    }

    private suspend fun SiopOpenId4VPConfig.presentationDefinition(
        presentationDefinitionSource: PresentationDefinitionSource,
    ): PresentationDefinition = presentationDefinitionResolver.resolve(presentationDefinitionSource, this)

    private suspend fun resolveClientMetaData(validated: ValidatedRequestObject): ValidatedClientMetaData {
        val source = checkNotNull(validated.clientMetaDataSource) { "Missing or invalid client metadata" }
        return clientMetadataValidator.validate(source, validated.responseMode)
    }
}
