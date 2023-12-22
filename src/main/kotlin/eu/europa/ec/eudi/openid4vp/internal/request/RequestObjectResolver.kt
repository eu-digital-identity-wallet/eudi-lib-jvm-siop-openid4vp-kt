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

import eu.europa.ec.eudi.openid4vp.JarmOption
import eu.europa.ec.eudi.openid4vp.ResolvedRequestObject
import eu.europa.ec.eudi.openid4vp.SiopOpenId4VPConfig
import eu.europa.ec.eudi.openid4vp.SubjectSyntaxType
import eu.europa.ec.eudi.openid4vp.internal.request.ValidatedRequestObject.*
import eu.europa.ec.eudi.prex.PresentationDefinition

internal class RequestObjectResolver(
    private val presentationDefinitionResolver: PresentationDefinitionResolver,
    private val clientMetadataValidator: ClientMetaDataValidator,
) {

    suspend fun resolve(
        validated: ValidatedRequestObject,
        siopOpenId4VPConfig: SiopOpenId4VPConfig,
    ): ResolvedRequestObject {
        val clientMetaData = resolveClientMetaData(validated)
        val jarmOption: JarmOption? = clientMetaData.jarmOption(siopOpenId4VPConfig)
        return when (validated) {
            is SiopAuthentication -> resolveIdTokenRequest(
                validated,
                clientMetaData.subjectSyntaxTypesSupported,
                jarmOption,
            )

            is OpenId4VPAuthorization -> resolveVpTokenRequest(validated, siopOpenId4VPConfig, jarmOption)
            is SiopOpenId4VPAuthentication -> resolveIdAndVpTokenRequest(
                validated,
                siopOpenId4VPConfig,
                clientMetaData.subjectSyntaxTypesSupported,
                jarmOption,
            )
        }
    }

    private suspend fun resolveIdAndVpTokenRequest(
        validated: SiopOpenId4VPAuthentication,
        siopOpenId4VPConfig: SiopOpenId4VPConfig,
        subjectSyntaxTypesSupported: List<SubjectSyntaxType>,
        jarmOption: JarmOption?,
    ): ResolvedRequestObject {
        val presentationDefinition = resolvePd(validated.presentationDefinitionSource, siopOpenId4VPConfig)
        return ResolvedRequestObject.SiopOpenId4VPAuthentication(
            idTokenType = validated.idTokenType,
            subjectSyntaxTypesSupported = subjectSyntaxTypesSupported,
            presentationDefinition = presentationDefinition,
            clientId = validated.clientId,
            state = validated.state,
            scope = validated.scope,
            nonce = validated.nonce,
            responseMode = validated.responseMode,
            jarmOption = jarmOption,
        )
    }

    private suspend fun resolveVpTokenRequest(
        validated: OpenId4VPAuthorization,
        siopOpenId4VPConfig: SiopOpenId4VPConfig,
        jarmOption: JarmOption?,
    ): ResolvedRequestObject {
        val presentationDefinition = resolvePd(validated.presentationDefinitionSource, siopOpenId4VPConfig)
        return ResolvedRequestObject.OpenId4VPAuthorization(
            presentationDefinition = presentationDefinition,
            clientId = validated.clientId,
            state = validated.state,
            nonce = validated.nonce,
            responseMode = validated.responseMode,
            jarmOption = jarmOption,
        )
    }

    private fun resolveIdTokenRequest(
        validated: SiopAuthentication,
        subjectSyntaxTypesSupported: List<SubjectSyntaxType>,
        jarmOption: JarmOption?,
    ): ResolvedRequestObject {
        return ResolvedRequestObject.SiopAuthentication(
            idTokenType = validated.idTokenType,
            subjectSyntaxTypesSupported = subjectSyntaxTypesSupported,
            clientId = validated.clientId,
            state = validated.state,
            scope = validated.scope,
            nonce = validated.nonce,
            responseMode = validated.responseMode,
            jarmOption = jarmOption,
        )
    }

    private suspend fun resolvePd(
        presentationDefinitionSource: PresentationDefinitionSource,
        siopOpenId4VPConfig: SiopOpenId4VPConfig,
    ): PresentationDefinition =
        presentationDefinitionResolver.resolve(presentationDefinitionSource, siopOpenId4VPConfig)

    private suspend fun resolveClientMetaData(validated: ValidatedRequestObject): ValidatedClientMetaData {
        val source = checkNotNull(validated.clientMetaDataSource) { "Missing or invalid client metadata" }
        return clientMetadataValidator.validate(source, validated.responseMode)
    }
}
