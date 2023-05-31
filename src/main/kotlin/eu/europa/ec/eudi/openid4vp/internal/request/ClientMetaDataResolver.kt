package eu.europa.ec.eudi.openid4vp.internal.request

import com.nimbusds.openid.connect.sdk.rp.OIDCClientMetadata
import eu.europa.ec.eudi.openid4vp.ClientMetaData
import eu.europa.ec.eudi.openid4vp.HttpGet
import eu.europa.ec.eudi.openid4vp.ResolutionError
import eu.europa.ec.eudi.openid4vp.asException
import eu.europa.ec.eudi.openid4vp.internal.mapError
import kotlinx.coroutines.CoroutineDispatcher
import java.net.URL

internal class ClientMetaDataResolver(
    ioCoroutineDispatcher: CoroutineDispatcher,
    private val getClientMetaData: HttpGet<ClientMetaData>,
) {
    private val clientMetadataValidator = ClientMetadataValidator(ioCoroutineDispatcher)
    suspend fun resolve(clientMetaDataSource: ClientMetaDataSource): Result<OIDCClientMetadata> {
        val clientMetaData = when (clientMetaDataSource) {
            is ClientMetaDataSource.ByValue -> clientMetaDataSource.metaData
            is ClientMetaDataSource.ByReference -> fetch(clientMetaDataSource.url).getOrThrow()
        }
        return clientMetadataValidator.validate(clientMetaData)
    }

    private suspend fun fetch(url: URL): Result<ClientMetaData> =
        getClientMetaData.get(url)
            .mapError { ResolutionError.UnableToFetchClientMetadata(it).asException() }
}
