package eu.europa.ec.euidw.openid4vp

import eu.europa.ec.euidw.prex.PresentationDefinition




sealed interface ResolutionError {
    data class PresentationDefinitionNotFoundForScope(val scope: Scope) : ResolutionError
    object FetchingPresentationDefinitionNotSupported : ResolutionError
    data class UnableToFetchPresentationDefinition(val cause: Throwable) : ResolutionError
}


interface AuthorizationRequestResolver {
    suspend fun resolve(validated: ValidatedOpenID4VPRequestData): Result<ResolvedOpenID4VPRequestData>
}

interface ClientMetaDataResolver {
    suspend fun resolve(validated: ValidatedOpenID4VPRequestData): Result<ClientMetaData>
}

internal class DefaultAuthorizationRequestResolver(
    private val presentationDefinitionResolver: PresentationDefinitionResolver,
    private val clientMetaDataResolver: ClientMetaDataResolver
) : AuthorizationRequestResolver {


    override suspend fun resolve(validated: ValidatedOpenID4VPRequestData): Result<ResolvedOpenID4VPRequestData> {
        val presentationDefinition = presentationDefinitionResolver.resolve(validated.presentationDefinitionSource).getOrThrow()
        val clientMetaData = clientMetaDataResolver.resolve(validated).getOrThrow()
        return ResolvedOpenID4VPRequestData(
            responseType = validated.responseType,
            presentationDefinition =  presentationDefinition,
            clientMetaData = clientMetaData,
            clientId = validated.clientId,
            state = validated.state,
            scope = validated.scope,
            nonce = validated.nonce,
            responseMode = validated.responseMode
        ).success()
    }

}


private fun ResolutionError.asException(): ResolutionException = ResolutionException(this)
private fun <T> ResolutionError.asFailure(): Result<T> = Result.failure(asException())
data class ResolutionException(val error: ResolutionError) : RuntimeException()




internal class PresentationDefinitionResolver(
    private val httpGetter: HttpGet<PresentationDefinition>,
    private val walletOpenId4VPConfig: WalletOpenId4VPConfig
) {

    suspend fun resolve(presentationDefinitionSource: PresentationDefinitionSource): Result<PresentationDefinition> =
        when (presentationDefinitionSource) {
            is PresentationDefinitionSource.PassByValue -> presentationDefinitionSource.presentationDefinition.success()
            is PresentationDefinitionSource.Implied -> lookupKnownPresentationDefinitions(presentationDefinitionSource.scope)
            is PresentationDefinitionSource.FetchByReference -> fetch(presentationDefinitionSource.url)
        }

    private fun lookupKnownPresentationDefinitions(scope: Scope): Result<PresentationDefinition> =
        scope.items()
            .firstNotNullOfOrNull { walletOpenId4VPConfig.knownPresentationDefinitionsPerScope[it] }
            ?.success()
            ?: ResolutionError.PresentationDefinitionNotFoundForScope(scope).asFailure()

    private suspend fun fetch(url: HttpsUrl): Result<PresentationDefinition> =
        if (walletOpenId4VPConfig.presentationDefinitionUriSupported)
            httpGetter.get(url).mapError { ResolutionError.UnableToFetchPresentationDefinition(it).asException() }
        else ResolutionError.FetchingPresentationDefinitionNotSupported.asFailure()
}