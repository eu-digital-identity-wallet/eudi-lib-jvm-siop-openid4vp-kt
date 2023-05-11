package eu.europa.ec.euidw.openid4vp.internal

import com.nimbusds.openid.connect.sdk.rp.OIDCClientMetadata
import eu.europa.ec.euidw.openid4vp.*


internal class ClientMetaDataResolver(
    private val getClientMetaData: HttpGet<ClientMetaData>,
    private val walletOpenId4VPConfig: WalletOpenId4VPConfig
) {

    private val validator : ClientMetadataValidator = ClientMetadataValidator(walletOpenId4VPConfig)

    suspend fun resolve(clientMetaDataSource: ClientMetaDataSource): Result<OIDCClientMetadata> {

        val clientMetaData = when (clientMetaDataSource) {
            is ClientMetaDataSource.PassByValue -> clientMetaDataSource.metaData
            is ClientMetaDataSource.FetchByReference -> fetch(clientMetaDataSource.url).getOrThrow()

        }
        return validator.validate(clientMetaData)
    }

    private suspend fun fetch(url: HttpsUrl): Result<ClientMetaData> =
        getClientMetaData.get(url.value)
            .mapError { ResolutionError.UnableToFetchClientMetadata(it).asException() }

}

