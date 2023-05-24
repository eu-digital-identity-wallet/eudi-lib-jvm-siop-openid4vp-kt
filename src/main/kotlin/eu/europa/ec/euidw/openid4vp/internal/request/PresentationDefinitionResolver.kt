package eu.europa.ec.euidw.openid4vp.internal.request

import eu.europa.ec.euidw.openid4vp.*
import eu.europa.ec.euidw.openid4vp.internal.mapError
import eu.europa.ec.euidw.openid4vp.internal.request.PresentationDefinitionSource.*
import eu.europa.ec.euidw.openid4vp.internal.success
import eu.europa.ec.euidw.prex.PresentationDefinition
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
    private val getPresentationDefinition: HttpGet<PresentationDefinition>
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
        config: WalletOpenId4VPConfig
    ): Result<PresentationDefinition> = when (source) {
        is ByValue -> source.presentationDefinition.success()
        is ByReference -> fetch(source.url, config)
        is Implied -> lookupKnownPresentationDefinitions(source.scope, config)
    }

    private fun lookupKnownPresentationDefinitions(
        scope: Scope,
        config: WalletOpenId4VPConfig
    ): Result<PresentationDefinition> =
        scope.items()
            .firstNotNullOfOrNull { config.knownPresentationDefinitionsPerScope[it] }
            ?.success()
            ?: ResolutionError.PresentationDefinitionNotFoundForScope(scope).asFailure()

    private suspend fun fetch(
        url: URL,
        config: WalletOpenId4VPConfig
    ): Result<PresentationDefinition> =
        if (config.presentationDefinitionUriSupported)
            withContext(Dispatchers.IO) {
                getPresentationDefinition.get(url)
                    .mapError { ResolutionError.UnableToFetchPresentationDefinition(it).asException() }
            }
        else ResolutionError.FetchingPresentationDefinitionNotSupported.asFailure()
}


