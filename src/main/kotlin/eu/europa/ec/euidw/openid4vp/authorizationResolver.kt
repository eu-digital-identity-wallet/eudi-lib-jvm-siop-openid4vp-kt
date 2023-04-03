package niscy.eudiw.openid4vp

import eu.europa.ec.euidw.openid4vp.HttpGet
import eu.europa.ec.euidw.openid4vp.PresentationDefinitionSource
import eu.europa.ec.euidw.openid4vp.WalletOpenId4VPConfig
import eu.europa.ec.euidw.openid4vp.success
import eu.europa.ec.euidw.prex.PresentationDefinition
import java.lang.IllegalStateException


class PresentationDefinitionSourceResolver(
    private val predefinedPDs: Map<String, PresentationDefinition> = emptyMap(),
    private val httpGetter: HttpGet<PresentationDefinition>,
    private val walletOpenId4VPConfig: WalletOpenId4VPConfig
) {

    suspend fun resolve(presentationDefinitionSource: PresentationDefinitionSource): Result<PresentationDefinition> {
        return when (presentationDefinitionSource) {
            is PresentationDefinitionSource.PassByValue -> presentationDefinitionSource.presentationDefinition.success()
            is PresentationDefinitionSource.Scopes ->
                presentationDefinitionSource.scopes.flatMap { scope ->
                    predefinedPDs[scope]?.let { listOf(it) } ?: emptyList()
                }.firstOrNull()?.success()
                    ?: Result.failure(IllegalArgumentException("Cannot find implied pd for scope ${presentationDefinitionSource.scopes}"))

            is PresentationDefinitionSource.FetchByReference ->
                if (walletOpenId4VPConfig.presentationDefinitionUriSupported)
                    httpGetter.get(presentationDefinitionSource.url)
                else Result.failure(IllegalStateException("Fetching of PD not supported"))
        }
    }
}