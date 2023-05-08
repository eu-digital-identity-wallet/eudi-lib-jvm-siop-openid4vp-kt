package eu.europa.ec.euidw.openid4vp

import com.eygraber.uri.Uri
import com.nimbusds.jose.Payload
import com.nimbusds.jwt.SignedJWT
import eu.europa.ec.euidw.openid4vp.internal.SiopId4VPRequestResolver
import eu.europa.ec.euidw.openid4vp.internal.SiopId4VPRequestValidator
import eu.europa.ec.euidw.openid4vp.internal.ValidatedSiopId4VPRequestObject
import eu.europa.ec.euidw.openid4vp.internal.utils.HttpGet
import eu.europa.ec.euidw.openid4vp.internal.utils.HttpsUrl
import eu.europa.ec.euidw.openid4vp.internal.utils.success
import eu.europa.ec.euidw.prex.PresentationDefinition
import io.ktor.client.*
import io.ktor.client.call.*
import io.ktor.client.engine.okhttp.*
import io.ktor.client.plugins.contentnegotiation.*
import io.ktor.client.request.*
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.jsonObject

sealed interface SiopId4VPRequest {

    data class Oauth2(val data: SiopId4VPRequestObject) : SiopId4VPRequest

    sealed interface JwtSecuredAuthorizationRequest : SiopId4VPRequest {
        data class PassByValue(val jwt: Jwt) : JwtSecuredAuthorizationRequest
        data class PassByReference(val jwtURI: HttpsUrl) : JwtSecuredAuthorizationRequest
    }

    companion object {

        private val json: Json by lazy { Json }
        fun make(uriStr: String): Result<SiopId4VPRequest> = runCatching {
            val uri = Uri.parse(uriStr)
            val requestValue = uri.getQueryParameter("request")
            val requestUriValue = uri.getQueryParameter("request_uri")

            when {
                !requestValue.isNullOrEmpty() -> JwtSecuredAuthorizationRequest.PassByValue(requestValue)
                !requestUriValue.isNullOrEmpty() -> HttpsUrl.make(requestUriValue)
                    .map { JwtSecuredAuthorizationRequest.PassByReference(it) }.getOrThrow()

                else -> makeOauth2(uri)
            }
        }

        private fun makeOauth2(uri: Uri): Oauth2 =
            Oauth2(
                SiopId4VPRequestObject(
                    responseType = uri.getQueryParameter("response_type"),
                    presentationDefinition = uri.getQueryParameter("presentation_definition"),
                    presentationDefinitionUri = uri.getQueryParameter("presentation_definition_uri"),
                    scope = uri.getQueryParameter("scope"),
                    nonce = uri.getQueryParameter("nonce"),
                    responseMode = uri.getQueryParameter("response_mode"),
                    clientIdScheme = uri.getQueryParameter("client_id_scheme"),
                    clientMetaData = uri.getQueryParameter("client_metadata"),
                    clientId = uri.getQueryParameter("client_id"),
                    responseUri = uri.getQueryParameter("response_uri"),
                    redirectUri = uri.getQueryParameter("redirect_uri"),
                    state = uri.getQueryParameter("state")
                )
            )
    }

}

sealed interface ResolvedRequestData {

    data class IdTokenRequestData(
        val idTokenType: List<IdTokenType>,
        val clientMetaData: ClientMetaData,
        val clientId: String,
        val nonce: String,
        val responseMode: ResponseMode,
        val state: String?,
        val scope: Scope?
    ) : ResolvedRequestData

    data class VpTokenRequestData(

        val presentationDefinition: PresentationDefinition,
        val clientMetaData: ClientMetaData,
        val clientId: String,
        val nonce: String,
        val responseMode: ResponseMode,
        val state: String?,
    ) : ResolvedRequestData

    data class IdAndVPTokenRequestData(
        val idTokenType: List<IdTokenType>,
        val presentationDefinition: PresentationDefinition,
        val clientMetaData: ClientMetaData,
        val clientId: String,
        val nonce: String,
        val responseMode: ResponseMode,
        val state: String?,
        val scope: Scope?
    ) : ResolvedRequestData
}

interface AuthorizationRequestResolver {
    suspend fun resolveRequest(
        request: SiopId4VPRequest
    ): Result<ResolvedRequestData>

    companion object {
        fun make(walletOpenId4VPConfig: WalletOpenId4VPConfig) : AuthorizationRequestResolver =
            AuthorizationRequestResolverImpl(walletOpenId4VPConfig)
    }
}

private class AuthorizationRequestResolverImpl(
    val walletOpenId4VPConfig: WalletOpenId4VPConfig
) : AuthorizationRequestResolver {

    private val ktorHttpClient = HttpClient(OkHttp) {
        install(ContentNegotiation) {}
    }

    private val httpGetter: HttpGet<String> = object : HttpGet<String> {
        override suspend fun get(url: HttpsUrl): Result<String> =
            runCatching {
                ktorHttpClient.get(url.value).body()
            }
    }

    override suspend fun resolveRequest(
        request: SiopId4VPRequest
    ): Result<ResolvedRequestData> {
        return runCatching {
            val unvalidated = data(request).getOrThrow()
            val validated = validate(unvalidated).getOrThrow()
            resolve(validated).getOrThrow()
        }
    }

    private suspend fun data(request: SiopId4VPRequest): Result<SiopId4VPRequestObject> = when (request) {
        is SiopId4VPRequest.Oauth2 -> request.data.success()
        is SiopId4VPRequest.JwtSecuredAuthorizationRequest.PassByValue -> fromJwt(request.jwt)
        is SiopId4VPRequest.JwtSecuredAuthorizationRequest.PassByReference -> fetch(request.jwtURI)
    }

    private fun fromJwt(jwt: Jwt): Result<SiopId4VPRequestObject> = runCatching {
        val tokenPayload = SignedJWT.parse(jwt).payload
        val jwtPayload = tokenPayload.toJSONObject()
        SiopId4VPRequestObject(
            responseType = jwtPayload["response_type"]?.toString(),
            presentationDefinition = extractInlineString(tokenPayload, "presentation_definition"),
            presentationDefinitionUri = jwtPayload["presentation_definition_uri"]?.toString(),
            scope = jwtPayload["scope"]?.toString(),
            nonce = jwtPayload["nonce"]?.toString(),
            responseMode = jwtPayload["response_mode"]?.toString(),
            clientIdScheme = jwtPayload["client_id_scheme"]?.toString(),
            clientMetaData = extractInlineString(tokenPayload, "client_metadata"),
            clientMetadataUri = jwtPayload["client_metadata_uri"]?.toString(),
            clientId = jwtPayload["client_id"]?.toString(),
            responseUri = jwtPayload["response_uri"]?.toString(),
            redirectUri = jwtPayload["redirect_uri"]?.toString(),
            state = jwtPayload["state"]?.toString(),
            supportedAlgorithm = jwtPayload["supported_algorithm"]?.toString(),
            idTokenType = jwtPayload["id_token_type"]?.toString()
        )
    }

    private fun extractInlineString(jwtPayload: Payload, elementName: String): String =
        Json.parseToJsonElement(jwtPayload.toString()).jsonObject[elementName]?.toString() ?: ""


    /**
     * Gets from URL the signed JWT and validates its signature. If successful generates the request object from the JWT payload
     */
    private suspend fun fetch(uri: HttpsUrl): Result<SiopId4VPRequestObject> = runCatching {
        val requestObject = httpGetter.get(uri).getOrThrow()
        fromJwt(requestObject).getOrThrow()
    }


    private fun validate(unvalidated: SiopId4VPRequestObject): Result<ValidatedSiopId4VPRequestObject> =
        SiopId4VPRequestValidator.validate(unvalidated)

    private suspend fun resolve(validated: ValidatedSiopId4VPRequestObject): Result<ResolvedRequestData> =
        SiopId4VPRequestResolver.resolve(validated, walletOpenId4VPConfig)


}