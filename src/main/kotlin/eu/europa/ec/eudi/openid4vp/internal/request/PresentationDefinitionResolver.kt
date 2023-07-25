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
import eu.europa.ec.eudi.openid4vp.internal.mapError
import eu.europa.ec.eudi.openid4vp.internal.request.PresentationDefinitionSource.*
import eu.europa.ec.eudi.openid4vp.internal.success
import eu.europa.ec.eudi.prex.PresentationDefinition
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.net.URL

/**
 * Resolves a [PresentationDefinitionSource] into a [PresentationDefinition]
 *
 * @param getPresentationDefinition a way of performing a HTTP GET to obtain a [PresentationDefinition] provided
 *  by [reference][PresentationDefinitionSource.ByReference]
 */
internal class PresentationDefinitionResolver(
    private val ioCoroutineDispatcher: CoroutineDispatcher = Dispatchers.IO,
    private val getPresentationDefinition: HttpGet<PresentationDefinition>,
) {

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
    suspend fun resolve(
        source: PresentationDefinitionSource,
        config: WalletOpenId4VPConfig,
    ): Result<PresentationDefinition> = when (source) {
        is ByValue -> source.presentationDefinition.success()
        is ByReference -> fetch(source.url, config)
        is Implied -> lookupKnownPresentationDefinitions(source.scope, config)
    }

    private fun lookupKnownPresentationDefinitions(
        scope: Scope,
        config: WalletOpenId4VPConfig,
    ): Result<PresentationDefinition> =
        scope.items()
            .firstNotNullOfOrNull { config.knownPresentationDefinitionsPerScope[it] }
            ?.success()
            ?: ResolutionError.PresentationDefinitionNotFoundForScope(scope).asFailure()

    @Suppress("ktlint")
    private suspend fun fetch(
        url: URL,
        config: WalletOpenId4VPConfig,
    ): Result<PresentationDefinition> =
        if (config.presentationDefinitionUriSupported) {
            withContext(ioCoroutineDispatcher) {
                getPresentationDefinition.get(url)
                    .mapError { ResolutionError.UnableToFetchPresentationDefinition(it).asException() }
            }
        } else {
            ResolutionError.FetchingPresentationDefinitionNotSupported.asFailure()
        }
}
