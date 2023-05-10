package eu.europa.ec.euidw.openid4vp.internal

import com.nimbusds.jose.shaded.gson.Gson
import com.nimbusds.jwt.SignedJWT
import eu.europa.ec.euidw.openid4vp.*
import eu.europa.ec.euidw.openid4vp.AuthorizationRequest.JwtSecured
import eu.europa.ec.euidw.openid4vp.AuthorizationRequest.JwtSecured.PassByReference
import eu.europa.ec.euidw.openid4vp.AuthorizationRequest.JwtSecured.PassByValue
import eu.europa.ec.euidw.openid4vp.AuthorizationRequest.NotSecured
import eu.europa.ec.euidw.prex.PresentationDefinition
import io.ktor.client.*
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.jsonObject

internal class AuthorizationRequestResolverImpl(
    private val walletOpenId4VPConfig: WalletOpenId4VPConfig,
    private val getRequestObjectJwt: HttpGet<String>,
    private val validatedRequestObjectResolver: ValidatedRequestObjectResolver
) : AuthorizationRequestResolver {


    override suspend fun resolveRequest(
        request: AuthorizationRequest
    ): Result<ResolvedRequestObject> = runCatching {
        val requestObject = requestObjectOf(request)
        val validatedRequestObject = RequestObjectValidator.validate(requestObject).getOrThrow()
        validatedRequestObjectResolver.resolve(validatedRequestObject, walletOpenId4VPConfig).getOrThrow()
    }


    private suspend fun requestObjectOf(request: AuthorizationRequest): RequestObject = when (request) {
        is NotSecured -> request.data
        is JwtSecured -> {
            val jwt = when (request) {
                is PassByValue -> request.jwt
                is PassByReference -> getRequestObjectJwt.get(request.jwtURI).getOrThrow()
            }
            val requestObject = requestObjectFromJwt(jwt)
            // Make sure that clientId of the initial request is the same
            // with the client id inside the request object
            require(request.clientId == requestObject.clientId) { "Invalid client_id. Expected ${request.clientId} found ${requestObject.clientId}" }
            requestObject
        }
    }

    companion object {
        internal fun make(
            client: HttpClient,
            walletOpenId4VPConfig: WalletOpenId4VPConfig
        ): AuthorizationRequestResolverImpl =
            make(ktor(client), ktor(client), ktor(client), walletOpenId4VPConfig)


        internal fun make(
            getRequestObjectJwt: HttpGet<String>,
            getPresentationDefinition: HttpGet<PresentationDefinition>,
            getClientMetaData: HttpGet<ClientMetaData>,
            walletOpenId4VPConfig: WalletOpenId4VPConfig
        ): AuthorizationRequestResolverImpl = AuthorizationRequestResolverImpl(
            walletOpenId4VPConfig = walletOpenId4VPConfig,
            getRequestObjectJwt = getRequestObjectJwt,
            validatedRequestObjectResolver = ValidatedRequestObjectResolver(
                presentationDefinitionResolver = PresentationDefinitionResolver(
                    getPresentationDefinition = getPresentationDefinition
                ),
                clientMetaDataResolver = ClientMetaDataResolver(
                    getClientMetaData = getClientMetaData
                )
            )

        )
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