package eu.europa.ec.euidw.openid4vp.internal

import com.nimbusds.jose.jwk.JWKSet
import com.nimbusds.openid.connect.sdk.rp.OIDCClientMetadata
import eu.europa.ec.euidw.openid4vp.*
import eu.europa.ec.euidw.openid4vp.internal.utils.HttpGet
import eu.europa.ec.euidw.openid4vp.internal.utils.HttpsUrl
import eu.europa.ec.euidw.openid4vp.internal.utils.mapError
import io.ktor.client.*
import io.ktor.client.call.*
import io.ktor.client.engine.okhttp.*
import io.ktor.client.plugins.contentnegotiation.*
import io.ktor.client.request.*
import java.lang.IllegalArgumentException
import java.net.URI


object ClientMetaDataResolver {

    private val ktorHttpClient = HttpClient(OkHttp) {
        install(ContentNegotiation) {}
    }

    private val httpGetter: HttpGet<ClientMetaData> = object : HttpGet<ClientMetaData> {
        override suspend fun get(url: HttpsUrl): Result<ClientMetaData> =
            runCatching {
                ktorHttpClient.get(url.value).body()
            }
    }

    suspend fun resolve(clientMetaDataSource: ClientMetaDataSource?): Result<OIDCClientMetadata> {
        return when (clientMetaDataSource) {
            is ClientMetaDataSource.PassByValue -> ClientMetadataValidator.validate(clientMetaDataSource.metaData)
            is ClientMetaDataSource.FetchByReference -> ClientMetadataValidator.validate(fetch(clientMetaDataSource.url).getOrThrow())
            else -> throw IllegalArgumentException("Client metadata info cannot be missing from request")
        }
    }

    private suspend fun fetch(url: HttpsUrl): Result<ClientMetaData> =
        httpGetter.get(url).mapError { ResolutionError.UnableToFetchClientMetadata(it).asException() }

}

private fun ResolutionError.asException(): ResolutionException = ResolutionException(this)