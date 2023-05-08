package eu.europa.ec.euidw.openid4vp.internal

import com.nimbusds.openid.connect.sdk.rp.OIDCClientMetadata
import eu.europa.ec.euidw.openid4vp.ClientMetaData
import eu.europa.ec.euidw.openid4vp.ClientMetaDataSource
import eu.europa.ec.euidw.openid4vp.ResolutionError
import eu.europa.ec.euidw.openid4vp.ResolutionException
import eu.europa.ec.euidw.openid4vp.internal.utils.HttpGet
import eu.europa.ec.euidw.openid4vp.internal.utils.HttpsUrl
import eu.europa.ec.euidw.openid4vp.internal.utils.mapError
import io.ktor.client.*
import io.ktor.client.call.*
import io.ktor.client.engine.okhttp.*
import io.ktor.client.plugins.contentnegotiation.*
import io.ktor.client.request.*


internal object ClientMetaDataResolver {


    suspend fun resolve(clientMetaDataSource: ClientMetaDataSource): Result<OIDCClientMetadata> {

        val clientMetaData = when (clientMetaDataSource) {
            is ClientMetaDataSource.PassByValue -> clientMetaDataSource.metaData
            is ClientMetaDataSource.FetchByReference -> fetch(clientMetaDataSource.url).getOrThrow()

        }

        return ClientMetadataValidator.validate(clientMetaData)
    }

    private suspend fun fetch(url: HttpsUrl): Result<ClientMetaData> =
        httpGetter.get(url).mapError { ResolutionError.UnableToFetchClientMetadata(it).asException() }

    private val httpGetter: HttpGet<ClientMetaData> by lazy {
        val ktorHttpClient = HttpClient(OkHttp) {
            install(ContentNegotiation) {}
        }
        object : HttpGet<ClientMetaData> {
            override suspend fun get(url: HttpsUrl): Result<ClientMetaData> =
                runCatching {
                    ktorHttpClient.get(url.value).body()
                }
        }
    }

}

private fun ResolutionError.asException(): ResolutionException = ResolutionException(this)