package eu.europa.ec.euidw.openid4vp.internal

import eu.europa.ec.euidw.openid4vp.*
import eu.europa.ec.euidw.openid4vp.internal.utils.HttpGet
import eu.europa.ec.euidw.openid4vp.internal.utils.HttpsUrl
import eu.europa.ec.euidw.openid4vp.internal.utils.mapError
import eu.europa.ec.euidw.openid4vp.internal.utils.success
import eu.europa.ec.euidw.prex.PresentationDefinition
import io.ktor.client.*
import io.ktor.client.call.*
import io.ktor.client.engine.okhttp.*
import io.ktor.client.plugins.contentnegotiation.*
import io.ktor.client.request.*

internal object PresentationDefinitionResolver {

    private val ktorHttpClient = HttpClient(OkHttp) {
        install(ContentNegotiation) {}
    }

    private val httpGetter: HttpGet<PresentationDefinition> =  object : HttpGet<PresentationDefinition> {
        override suspend fun get(url: HttpsUrl): Result<PresentationDefinition> =
            runCatching {
                ktorHttpClient.get(url.value).body()
            }
    }

    suspend fun resolve(presentationDefinitionSource: PresentationDefinitionSource, walletOpenId4VPConfig: WalletOpenId4VPConfig): Result<PresentationDefinition> =
        when (presentationDefinitionSource) {
            is PresentationDefinitionSource.PassByValue -> presentationDefinitionSource.presentationDefinition.success()
            is PresentationDefinitionSource.Implied -> lookupKnownPresentationDefinitions(presentationDefinitionSource.scope, walletOpenId4VPConfig)
            is PresentationDefinitionSource.FetchByReference -> fetch(presentationDefinitionSource.url, walletOpenId4VPConfig)
        }

    private fun lookupKnownPresentationDefinitions(scope: Scope, walletOpenId4VPConfig: WalletOpenId4VPConfig): Result<PresentationDefinition> =
        scope.items()
            .firstNotNullOfOrNull { walletOpenId4VPConfig.knownPresentationDefinitionsPerScope[it] }
            ?.success()
            ?: ResolutionError.PresentationDefinitionNotFoundForScope(scope).asFailure()

    private suspend fun fetch(url: HttpsUrl, walletOpenId4VPConfig: WalletOpenId4VPConfig): Result<PresentationDefinition> =
        if (walletOpenId4VPConfig.presentationDefinitionUriSupported)
            httpGetter.get(url).mapError { ResolutionError.UnableToFetchPresentationDefinition(it).asException() }
        else ResolutionError.FetchingPresentationDefinitionNotSupported.asFailure()
}

private fun ResolutionError.asException(): ResolutionException = ResolutionException(this)
private fun <T> ResolutionError.asFailure(): Result<T> = Result.failure(asException())