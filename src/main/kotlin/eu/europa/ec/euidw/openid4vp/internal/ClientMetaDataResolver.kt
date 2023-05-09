package eu.europa.ec.euidw.openid4vp.internal

import com.nimbusds.openid.connect.sdk.rp.OIDCClientMetadata
import eu.europa.ec.euidw.openid4vp.ClientMetaData
import eu.europa.ec.euidw.openid4vp.ClientMetaDataSource
import eu.europa.ec.euidw.openid4vp.ResolutionError
import eu.europa.ec.euidw.openid4vp.ResolutionException


internal object ClientMetaDataResolver {


    suspend fun resolve(clientMetaDataSource: ClientMetaDataSource): Result<OIDCClientMetadata> {

        val clientMetaData = when (clientMetaDataSource) {
            is ClientMetaDataSource.PassByValue -> clientMetaDataSource.metaData
            is ClientMetaDataSource.FetchByReference -> fetch(clientMetaDataSource.url).getOrThrow()

        }

        return ClientMetadataValidator.validate(clientMetaData)
    }

    private suspend fun fetch(url: HttpsUrl): Result<ClientMetaData> =
        HttpGet.ktor<ClientMetaData>().get(url)
            .mapError { ResolutionError.UnableToFetchClientMetadata(it).asException() }

}

private fun ResolutionError.asException(): ResolutionException = ResolutionException(this)