package eu.europa.ec.eudi.openid4vp.internal.request

import com.nimbusds.jose.shaded.gson.Gson
import com.nimbusds.jwt.SignedJWT
import eu.europa.ec.eudi.openid4vp.*
import eu.europa.ec.eudi.openid4vp.AuthorizationRequest.JwtSecured
import eu.europa.ec.eudi.openid4vp.AuthorizationRequest.JwtSecured.PassByReference
import eu.europa.ec.eudi.openid4vp.AuthorizationRequest.JwtSecured.PassByValue
import eu.europa.ec.eudi.openid4vp.AuthorizationRequest.NotSecured
import eu.europa.ec.eudi.prex.PresentationDefinition
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.jsonObject

internal class DefaultAuthorizationRequestResolver(
    private val ioCoroutineDispatcher: CoroutineDispatcher,
    private val walletOpenId4VPConfig: WalletOpenId4VPConfig,
    private val getRequestObjectJwt: HttpGet<String>,
    private val validatedRequestObjectResolver: ValidatedRequestObjectResolver,
) : AuthorizationRequestResolver {

    override suspend fun resolveRequest(
        request: AuthorizationRequest,
    ): Resolution =
        try {
            val requestObject = requestObjectOf(request)
            val validatedRequestObject = RequestObjectValidator.validate(requestObject).getOrThrow()
            val resolved =
                validatedRequestObjectResolver.resolve(validatedRequestObject, walletOpenId4VPConfig).getOrThrow()
            Resolution.Success(resolved)
        } catch (t: AuthorizationRequestException) {
            Resolution.Invalid(t.error)
        }

    /**
     * Extracts the [request object][RequestObject] of an [AuthorizationRequest]
     */
    private suspend fun requestObjectOf(request: AuthorizationRequest): RequestObject {
        suspend fun fetchJwt(request: PassByReference): Jwt =
            withContext(ioCoroutineDispatcher) {
                getRequestObjectJwt.get(request.jwtURI).getOrThrow()
            }

        return when (request) {
            is NotSecured -> request.requestObject
            is JwtSecured -> {
                val jwt = when (request) {
                    is PassByValue -> request.jwt
                    is PassByReference -> fetchJwt(request)
                }
                val requestObject = requestObjectFromJwt(jwt)
                // Make sure that clientId of the initial request is the same
                // with the client id inside the request object
                require(request.clientId == requestObject.clientId) {
                    "Invalid client_id. Expected ${request.clientId} found ${requestObject.clientId}"
                }

                requestObject.also { println("Warning JWT signature not verified") }
            }
        }
    }

    companion object {

        /**
         * Factory method for creating a [DefaultAuthorizationRequestResolver]
         */
        internal fun make(
            ioCoroutineDispatcher: CoroutineDispatcher = Dispatchers.IO,
            getRequestObjectJwt: HttpGet<String>,
            getPresentationDefinition: HttpGet<PresentationDefinition>,
            getClientMetaData: HttpGet<ClientMetaData>,
            walletOpenId4VPConfig: WalletOpenId4VPConfig,
        ): DefaultAuthorizationRequestResolver = DefaultAuthorizationRequestResolver(
            ioCoroutineDispatcher = ioCoroutineDispatcher,
            walletOpenId4VPConfig = walletOpenId4VPConfig,
            getRequestObjectJwt = getRequestObjectJwt,
            validatedRequestObjectResolver = ValidatedRequestObjectResolver(
                presentationDefinitionResolver = PresentationDefinitionResolver(
                    ioCoroutineDispatcher = ioCoroutineDispatcher,
                    getPresentationDefinition = getPresentationDefinition,
                ),
                clientMetaDataResolver = ClientMetaDataResolver(
                    ioCoroutineDispatcher = ioCoroutineDispatcher,
                    getClientMetaData = getClientMetaData,
                ),
            ),

        )
    }
}

/**
 * Extracts the request object from a [jwt]
 *
 * Currently, method neither verify signature nor supports
 * encrypted JARs
 */
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
            idTokenType = getStringClaim("id_token_type"),
        )
    }
}
