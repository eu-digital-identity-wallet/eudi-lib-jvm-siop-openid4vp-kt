package eu.europa.ec.euidw.openid4vp.internal

import com.nimbusds.jose.shaded.gson.Gson
import com.nimbusds.jwt.SignedJWT
import eu.europa.ec.euidw.openid4vp.*
import eu.europa.ec.euidw.openid4vp.AuthorizationRequest.JwtSecured
import eu.europa.ec.euidw.openid4vp.AuthorizationRequest.JwtSecured.PassByReference
import eu.europa.ec.euidw.openid4vp.AuthorizationRequest.JwtSecured.PassByValue
import eu.europa.ec.euidw.openid4vp.AuthorizationRequest.NotSecured
import eu.europa.ec.euidw.openid4vp.internal.utils.HttpGet
import io.ktor.client.*
import io.ktor.client.call.*
import io.ktor.client.engine.okhttp.*
import io.ktor.client.plugins.contentnegotiation.*
import io.ktor.client.request.*
import io.ktor.http.*
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.jsonObject

internal class AuthorizationRequestResolverImpl(
    private val walletOpenId4VPConfig: WalletOpenId4VPConfig
) : AuthorizationRequestResolver {


    override suspend fun resolveRequest(
        request: AuthorizationRequest
    ): Result<ResolvedRequestObject> = runCatching {
        val requestObject = requestObjectOf(request)
        val validatedRequestObject = RequestObjectValidator.validate(requestObject).getOrThrow()
        ValidatedRequestObjectResolver.resolve(validatedRequestObject, walletOpenId4VPConfig).getOrThrow()
    }


    private suspend fun requestObjectOf(request: AuthorizationRequest): RequestObject = when (request) {
        is NotSecured -> request.data
        is JwtSecured -> {
            val jwt = when (request) {
                is PassByValue -> request.jwt
                is PassByReference -> httpGetter.get(request.jwtURI).getOrThrow()
            }
            val requestObject = requestObjectFromJwt(jwt)
            // Make sure that clientId of the initial request is the same
            // with the client id inside the request object
            require(request.clientId == requestObject.clientId) { "Invalid client_id. Expected ${request.clientId} found ${requestObject.clientId}" }
            requestObject
        }
    }


    private val httpGetter: HttpGet<String> by lazy {
        val ktorHttpClient = HttpClient(OkHttp) {
            install(ContentNegotiation) {}
        }
        HttpGet { url ->
            runCatching {
                val response = ktorHttpClient.get(url.value)
                if (response.status == HttpStatusCode.OK) response.body()
                else throw RuntimeException("Failed to get ${url}. Http Code = ${response.status}")
            }
        }
    }

}

private fun requestObjectFromJwt(jwt: Jwt): RequestObject {

    val signedJwt = SignedJWT.parse(jwt)
    fun Map<String, Any?>.asJsonObject(): JsonObject {
        val jsonStr = Gson().toJson(this)
        return Json.parseToJsonElement(jsonStr).jsonObject
    }

    return with(signedJwt.jwtClaimsSet) {
        RequestObject(
            responseType = getStringClaim("response_type"),
            presentationDefinition = getJSONObjectClaim("presentation_definition")?.asJsonObject(),
            presentationDefinitionUri = getStringClaim("presentation_definition_uri"),
            scope = getStringClaim("scope"),
            nonce = getStringClaim("nonce"),
            responseMode = getStringClaim("response_mode"),
            clientIdScheme = getStringClaim("client_id_scheme"),
            clientMetaData = getJSONObjectClaim("client_metadata")?.asJsonObject(),
            clientMetadataUri = getStringClaim("client_metadata_uri"),
            clientId = getStringClaim("client_id"),
            responseUri = getStringClaim("response_uri"),
            redirectUri = getStringClaim("redirect_uri"),
            state = getStringClaim("state"),
            supportedAlgorithm = getStringClaim("supported_algorithm"),
            idTokenType = getStringClaim("id_token_type")
        )
    }

}