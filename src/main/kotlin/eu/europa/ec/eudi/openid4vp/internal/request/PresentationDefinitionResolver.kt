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
import eu.europa.ec.eudi.openid4vp.internal.request.PresentationDefinitionSource.*
import eu.europa.ec.eudi.prex.PresentationDefinition
import io.ktor.client.*
import io.ktor.client.call.*
import io.ktor.client.request.*
import kotlinx.coroutines.coroutineScope
import java.net.URL

/**
 * Resolves a [PresentationDefinitionSource] into a [PresentationDefinition]
 * If the [source] is
 * - [PresentationDefinitionSource.ByValue] method returns [PresentationDefinitionSource.ByValue.presentationDefinition]
 * - [PresentationDefinitionSource.ByReference] methods fetches presentation definition from verifier's [end-point][PresentationDefinitionSource.ByReference.url]
 * - [PresentationDefinitionSource.Implied] method checks [config] to find a pre-agreed presentation definition
 *
 * Depending on the source the following [errors][ResolutionError] can be raised as [AuthorizationRequestException]
 * - [ResolutionError.UnableToFetchPresentationDefinition]
 * - [ResolutionError.FetchingPresentationDefinitionNotSupported]
 * - [ResolutionError.PresentationDefinitionNotFoundForScope]
 *
 * @param source the source of presentation definition to be resolved
 * @return the presentation definition or a [ResolutionError] wrapped within a [AuthorizationRequestException]
 *
 */
internal suspend fun HttpClient.resolvePresentationDefinition(
    source: PresentationDefinitionSource,
    config: SiopOpenId4VPConfig,
): PresentationDefinition = coroutineScope {
    when (source) {
        is ByValue -> source.presentationDefinition
        is ByReference ->
            if (config.vpConfiguration.presentationDefinitionUriSupported) fetchPresentationDefinition(source.url)
            else throw ResolutionError.FetchingPresentationDefinitionNotSupported.asException()

        is Implied -> lookupKnownPresentationDefinitions(source.scope, config)
    }
}

private fun lookupKnownPresentationDefinitions(
    scope: Scope,
    config: SiopOpenId4VPConfig,
): PresentationDefinition =
    scope.items()
        .firstNotNullOfOrNull { config.vpConfiguration.knownPresentationDefinitionsPerScope[it] }
        ?: throw ResolutionError.PresentationDefinitionNotFoundForScope(scope).asException()

private suspend fun HttpClient.fetchPresentationDefinition(url: URL): PresentationDefinition =
    try {
        get(url).body()
    } catch (t: Throwable) {
        throw ResolutionError.UnableToFetchPresentationDefinition(t).asException()
    }
