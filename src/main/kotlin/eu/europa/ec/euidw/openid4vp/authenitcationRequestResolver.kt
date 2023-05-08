package eu.europa.ec.euidw.openid4vp

import com.eygraber.uri.Uri
import com.nimbusds.jose.shaded.gson.Gson
import com.nimbusds.jwt.SignedJWT
import com.nimbusds.oauth2.sdk.util.JSONObjectUtils
import com.nimbusds.oauth2.sdk.util.JSONUtils
import com.nimbusds.openid.connect.sdk.AuthenticationRequest
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
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.jsonObject

sealed interface AuthorizationRequest {

    data class NotSecured(val data: RequestObject) : AuthorizationRequest

    sealed interface JwtSecured : AuthorizationRequest {
        data class PassByValue(val jwt: Jwt) : JwtSecured
        data class PassByReference(val jwtURI: HttpsUrl) : JwtSecured
    }

    companion object {

        private val json: Json = Json

        fun make(uriStr: String): Result<AuthorizationRequest> = runCatching {
            val uri = Uri.parse(uriStr)
            val requestValue = uri.getQueryParameter("request")
            val requestUriValue = uri.getQueryParameter("request_uri")

            when {
                !requestValue.isNullOrEmpty() -> JwtSecured.PassByValue(requestValue)
                !requestUriValue.isNullOrEmpty() -> HttpsUrl.make(requestUriValue)
                    .map { JwtSecured.PassByReference(it) }.getOrThrow()

                else -> makeOauth2(uri)
            }
        }

        private fun makeOauth2(uri: Uri): NotSecured {

            fun jsonObject(p: String): JsonObject? =
                uri.getQueryParameter(p)?.let { json.parseToJsonElement(it).jsonObject }

            return NotSecured(
                RequestObject(
                    responseType = uri.getQueryParameter("response_type"),
                    presentationDefinition = jsonObject("presentation_definition"),
                    presentationDefinitionUri = uri.getQueryParameter("presentation_definition_uri"),
                    scope = uri.getQueryParameter("scope"),
                    nonce = uri.getQueryParameter("nonce"),
                    responseMode = uri.getQueryParameter("response_mode"),
                    clientIdScheme = uri.getQueryParameter("client_id_scheme"),
                    clientMetaData = jsonObject("client_metadata"),
                    clientId = uri.getQueryParameter("client_id"),
                    responseUri = uri.getQueryParameter("response_uri"),
                    redirectUri = uri.getQueryParameter("redirect_uri"),
                    state = uri.getQueryParameter("state")
                )
            )
        }
    }

}

sealed interface ResolvedRequestObject {

    data class IdTokenRequestObject(
        val idTokenType: List<IdTokenType>,
        val clientMetaData: ClientMetaData,
        val clientId: String,
        val nonce: String,
        val responseMode: ResponseMode,
        val state: String,
        val scope: Scope
    ) : ResolvedRequestObject

    data class VpTokenRequestObject(

        val presentationDefinition: PresentationDefinition,
        val clientMetaData: ClientMetaData,
        val clientId: String,
        val nonce: String,
        val responseMode: ResponseMode,
        val state: String,
    ) : ResolvedRequestObject

    data class IdAndVPTokenRequestObject(
        val idTokenType: List<IdTokenType>,
        val presentationDefinition: PresentationDefinition,
        val clientMetaData: ClientMetaData,
        val clientId: String,
        val nonce: String,
        val responseMode: ResponseMode,
        val state: String,
        val scope: Scope
    ) : ResolvedRequestObject
}

interface AuthorizationRequestResolver {
    suspend fun resolveRequest(
        request: AuthorizationRequest
    ): Result<ResolvedRequestObject>

    companion object {
        fun make(walletOpenId4VPConfig: WalletOpenId4VPConfig): AuthorizationRequestResolver =
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
        request: AuthorizationRequest
    ): Result<ResolvedRequestObject> {
        return runCatching {
            val unvalidated = data(request).getOrThrow()
            val validated = validate(unvalidated).getOrThrow()
            resolve(validated).getOrThrow()
        }
    }

    private suspend fun data(request: AuthorizationRequest): Result<RequestObject> = when (request) {
        is AuthorizationRequest.NotSecured -> request.data.success()
        is AuthorizationRequest.JwtSecured.PassByValue -> fromJwt(request.jwt)
        is AuthorizationRequest.JwtSecured.PassByReference -> fetch(request.jwtURI)
    }

    private fun fromJwt(jwt: Jwt): Result<RequestObject> = runCatching {
        val signedJwt = SignedJWT.parse(jwt)
        val claimSet = signedJwt.jwtClaimsSet
        fun Map<String, Any?>.asJsonObject(): JsonObject {
            val jsonStr = Gson().toJson(this)
            return Json.parseToJsonElement(jsonStr).jsonObject
        }

        RequestObject(
            responseType = claimSet.getStringClaim("response_type"),
            presentationDefinition = claimSet.getJSONObjectClaim("presentation_definition")?.asJsonObject(),
            presentationDefinitionUri = claimSet.getStringClaim("presentation_definition_uri"),
            scope = claimSet.getStringClaim("scope"),
            nonce = claimSet.getStringClaim("nonce"),
            responseMode = claimSet.getStringClaim("response_mode"),
            clientIdScheme = claimSet.getStringClaim("client_id_scheme"),
            clientMetaData = claimSet.getJSONObjectClaim("client_metadata")?.asJsonObject(),
            clientMetadataUri = claimSet.getStringClaim("client_metadata_uri"),
            clientId = claimSet.getStringClaim("client_id"),
            responseUri = claimSet.getStringClaim("response_uri"),
            redirectUri = claimSet.getStringClaim("redirect_uri"),
            state = claimSet.getStringClaim("state"),
            supportedAlgorithm = claimSet.getStringClaim("supported_algorithm"),
            idTokenType = claimSet.getStringClaim("id_token_type")
        )
    }


    /**
     * Gets from URL the signed JWT and validates its signature. If successful generates the request object from the JWT payload
     */
    private suspend fun fetch(uri: HttpsUrl): Result<RequestObject> = runCatching {
        val requestObject = httpGetter.get(uri).getOrThrow()
        fromJwt(requestObject).getOrThrow()
    }


    private fun validate(unvalidated: RequestObject): Result<ValidatedSiopId4VPRequestObject> =
        SiopId4VPRequestValidator.validate(unvalidated)

    private suspend fun resolve(validated: ValidatedSiopId4VPRequestObject): Result<ResolvedRequestObject> =
        SiopId4VPRequestResolver.resolve(validated, walletOpenId4VPConfig)


}