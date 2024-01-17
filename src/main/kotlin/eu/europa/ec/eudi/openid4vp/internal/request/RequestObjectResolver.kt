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
import eu.europa.ec.eudi.prex.PresentationDefinition
import io.ktor.client.*

internal suspend fun HttpClient.resolveRequestObject(
    siopOpenId4VPConfig: SiopOpenId4VPConfig,
    validated: ValidatedRequestObject,
): ResolvedRequestObject {
    val clientMetaData = resolveClientMetaData(validated)
    return when (validated) {
        is SiopAuthentication -> resolveIdTokenRequest(siopOpenId4VPConfig, validated, clientMetaData)
        is OpenId4VPAuthorization -> resolveVpTokenRequest(siopOpenId4VPConfig, validated, clientMetaData)
        is SiopOpenId4VPAuthentication -> resolveIdAndVpTokenRequest(siopOpenId4VPConfig, validated, clientMetaData)
    }
}

private suspend fun HttpClient.resolveIdAndVpTokenRequest(
    siopOpenId4VPConfig: SiopOpenId4VPConfig,
    request: SiopOpenId4VPAuthentication,
    clientMetaData: ValidatedClientMetaData,
): ResolvedRequestObject {
    val presentationDefinition = presentationDefinition(siopOpenId4VPConfig, request.presentationDefinitionSource)
    return ResolvedRequestObject.SiopOpenId4VPAuthentication(
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

private suspend fun HttpClient.resolveVpTokenRequest(
    siopOpenId4VPConfig: SiopOpenId4VPConfig,
    authorization: OpenId4VPAuthorization,
    clientMetaData: ValidatedClientMetaData,
): ResolvedRequestObject {
    val presentationDefinition = presentationDefinition(
        siopOpenId4VPConfig,
        authorization.presentationDefinitionSource,
    )
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
    siopOpenId4VPConfig: SiopOpenId4VPConfig,
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

private suspend fun HttpClient.presentationDefinition(
    siopOpenId4VPConfig: SiopOpenId4VPConfig,
    presentationDefinitionSource: PresentationDefinitionSource,
): PresentationDefinition =
    resolvePresentationDefinition(presentationDefinitionSource, siopOpenId4VPConfig)

private suspend fun HttpClient.resolveClientMetaData(validated: ValidatedRequestObject): ValidatedClientMetaData {
    val source = checkNotNull(validated.clientMetaDataSource) { "Missing or invalid client metadata" }
    return validateClientMetaData(source, validated.responseMode)
}
