package eu.europa.ec.euidw.openid4vp.internal.request

import eu.europa.ec.euidw.openid4vp.*
import eu.europa.ec.euidw.openid4vp.internal.mapError
import eu.europa.ec.euidw.openid4vp.internal.request.PresentationDefinitionSource.*
import eu.europa.ec.euidw.openid4vp.internal.success
import eu.europa.ec.euidw.prex.PresentationDefinition

internal class PresentationDefinitionResolver(
    private val getPresentationDefinition: HttpGet<PresentationDefinition>
) {


    suspend fun resolve(
        presentationDefinitionSource: PresentationDefinitionSource,
        walletOpenId4VPConfig: WalletOpenId4VPConfig
    ): Result<PresentationDefinition> =
        when (presentationDefinitionSource) {
            is PassByValue -> presentationDefinitionSource.presentationDefinition.success()
            is Implied -> lookupKnownPresentationDefinitions(presentationDefinitionSource.scope, walletOpenId4VPConfig)
            is FetchByReference -> fetch(presentationDefinitionSource.url, walletOpenId4VPConfig)
        }

    private fun lookupKnownPresentationDefinitions(
        scope: Scope,
        walletOpenId4VPConfig: WalletOpenId4VPConfig
    ): Result<PresentationDefinition> =
        scope.items()
            .firstNotNullOfOrNull { walletOpenId4VPConfig.knownPresentationDefinitionsPerScope[it] }
            ?.success()
            ?: ResolutionError.PresentationDefinitionNotFoundForScope(scope).asFailure()

    private suspend fun fetch(
        url: HttpsUrl,
        walletOpenId4VPConfig: WalletOpenId4VPConfig
    ): Result<PresentationDefinition> =
        if (walletOpenId4VPConfig.presentationDefinitionUriSupported)
            getPresentationDefinition.get(url.value)
                .mapError { ResolutionError.UnableToFetchPresentationDefinition(it).asException() }
        else ResolutionError.FetchingPresentationDefinitionNotSupported.asFailure()
}


