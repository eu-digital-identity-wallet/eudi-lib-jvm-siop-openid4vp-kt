package eu.europa.ec.euidw.openid4vp

import com.eygraber.uri.Uri
import com.nimbusds.openid.connect.sdk.rp.OIDCClientMetadata
import eu.europa.ec.euidw.openid4vp.AuthorizationRequest.JwtSecured.PassByReference
import eu.europa.ec.euidw.openid4vp.AuthorizationRequest.JwtSecured.PassByValue
import eu.europa.ec.euidw.openid4vp.ResolvedRequestObject.SiopOpenId4VPAuthentication
import eu.europa.ec.euidw.openid4vp.ResolvedRequestObject.OpenId4VPAuthorization
import eu.europa.ec.euidw.openid4vp.internal.DefaultAuthorizationRequestResolver
import eu.europa.ec.euidw.openid4vp.internal.ktor.KtorAuthorizationRequestResolver
import eu.europa.ec.euidw.prex.PresentationDefinition
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.jsonObject
import java.io.Closeable
import java.lang.IllegalStateException

/**
 * OAUTH2 authorization request
 *
 * This is merely a data carrier structure which doesn't enforce any rules.
 */
sealed interface AuthorizationRequest {

    data class NotSecured(val requestObject: RequestObject) : AuthorizationRequest

    /**
     * JWT Secured authorization request (JAR)
     */
    sealed interface JwtSecured : AuthorizationRequest {
        /**
         * The <em>client_id</em> of the relying party (verifier)
         */
        val clientId: String

        /**
         * A JAR passed by value
         */
        data class PassByValue(override val clientId: String, val jwt: Jwt) : JwtSecured

        /**
         * A JAR passed by reference
         */
        data class PassByReference(override val clientId: String, val jwtURI: HttpsUrl) : JwtSecured
    }

    companion object {

        /**
         * Convenient method for parsing a URI representing an OAUTH2 Authorization request.
         */
        fun make(uriStr: String): Result<AuthorizationRequest> = runCatching {
            val uri = Uri.parse(uriStr)
            fun clientId(): String =
                uri.getQueryParameter("client_id")
                    ?: throw RequestValidationError.MissingClientId.asException()

            val requestValue = uri.getQueryParameter("request")
            val requestUriValue = uri.getQueryParameter("request_uri")

            when {
                !requestValue.isNullOrEmpty() -> PassByValue(clientId(), requestValue)
                !requestUriValue.isNullOrEmpty() -> HttpsUrl.make(requestUriValue)
                    .map { PassByReference(clientId(), it) }.getOrThrow()

                else -> notSecured(uri)
            }
        }

        /**
         * Populates a [NotSecured] from the query parameters of the given [uri]
         */
        private fun notSecured(uri: Uri): NotSecured {

            fun jsonObject(p: String): JsonObject? =
                uri.getQueryParameter(p)?.let { Json.parseToJsonElement(it).jsonObject }

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

/**
 * Represents an OAUTH2 authorization request. In particular
 * either a [SIOPv2 for id_token][SiopOpenId4VPAuthentication] or
 * a [OpenId4VP for vp_token][OpenId4VPAuthorization] or
 * a [SIOPv2 combined with OpenID4VP][SiopOpenId4VPAuthentication]
 */
sealed interface ResolvedRequestObject {

    val responseMode: ResponseMode
    val state: String

    /**
     * SIOPv2 Authentication request for issuing an id_token
     */
    data class SiopAuthentication(
        val idTokenType: List<IdTokenType>,
        val clientMetaData: OIDCClientMetadata,
        val clientId: String,
        val nonce: String,
        override val responseMode: ResponseMode,
        override val state: String,
        val scope: Scope
    ) : ResolvedRequestObject

    /**
     * OpenId4VP Authorization request for presenting a vp_token
     */
    data class OpenId4VPAuthorization(
        val presentationDefinition: PresentationDefinition,
        val clientMetaData: OIDCClientMetadata,
        val clientId: String,
        val nonce: String,
        override val responseMode: ResponseMode,
        override val state: String,
    ) : ResolvedRequestObject

    /**
     * OpenId4VP combined with SIOPv2 request for presenting an id_token & vp_token
     */
    data class SiopOpenId4VPAuthentication(
        val idTokenType: List<IdTokenType>,
        val presentationDefinition: PresentationDefinition,
        val clientMetaData: OIDCClientMetadata,
        val clientId: String,
        val nonce: String,
        override val responseMode: ResponseMode,
        override val state: String,
        val scope: Scope
    ) : ResolvedRequestObject
}

sealed interface AuthorizationRequestError
sealed interface RequestValidationError : AuthorizationRequestError {

    //
    // Response Type errors
    //
    data class UnsupportedResponseType(val value: String) : RequestValidationError
    object MissingResponseType : RequestValidationError

    //
    // Response Mode errors
    //
    data class UnsupportedResponseMode(val value: String?) : RequestValidationError

    //
    // Presentation Definition errors
    //
    object MissingPresentationDefinition : RequestValidationError
    data class InvalidPresentationDefinition(val cause: Throwable) : RequestValidationError
    object InvalidPresentationDefinitionUri : RequestValidationError
    object InvalidRedirectUri : RequestValidationError
    object MissingRedirectUri : RequestValidationError
    object MissingResponseUri : RequestValidationError
    object InvalidResponseUri : RequestValidationError
    object ResponseUriMustNotBeProvided : RequestValidationError
    object RedirectUriMustNotBeProvided : RequestValidationError
    object MissingState : RequestValidationError
    object MissingNonce : RequestValidationError
    object MissingScope : RequestValidationError
    object MissingClientId : RequestValidationError

    object InvalidClientMetaDataUri : RequestValidationError
    object OneOfClientMedataOrUri : RequestValidationError
    object SubjectSyntaxTypesNoMatch : RequestValidationError
    object MissingClientMetadataJwksSource : RequestValidationError
    object BothJwkUriAndInlineJwks : RequestValidationError
    object SubjectSyntaxTypesWrongSyntax : RequestValidationError
    data class InvalidClientIdScheme(val value: String) : RequestValidationError

}

sealed interface ResolutionError : AuthorizationRequestError {
    data class PresentationDefinitionNotFoundForScope(val scope: Scope) : ResolutionError
    object FetchingPresentationDefinitionNotSupported : ResolutionError
    data class UnableToFetchPresentationDefinition(val cause: Throwable) : ResolutionError
    data class UnableToFetchClientMetadata(val cause: Throwable) : ResolutionError
    data class UnableToFetchRequestObject(val cause: Throwable) : ResolutionError
    data class ClientMetadataJwkUriUnparsable(val cause: Throwable) : ResolutionError
    data class ClientMetadataJwkResolutionFailed(val cause: Throwable) : ResolutionError
}


fun AuthorizationRequestError.asException(): AuthorizationRequestException =
    AuthorizationRequestException(this)

fun <T> AuthorizationRequestError.asFailure(): Result<T> =
    Result.failure(asException())


data class AuthorizationRequestException(val error: AuthorizationRequestError) : RuntimeException()

sealed interface Resolution {
    data class Success(val data: ResolvedRequestObject) : Resolution
    data class Invalid(val error: AuthorizationRequestError) : Resolution
}

fun interface AuthorizationRequestResolver {

    /**
     * Tries to validate and resolve the provided [uri] into
     * a [ResolvedRequestObject]
     */
    suspend fun resolveRequestUri(uri: String): Resolution = runCatching {
        AuthorizationRequest.make(uri).getOrThrow()
    }.fold(
        onSuccess = { resolveRequest(it) },
        onFailure = {
            when (it) {
                is AuthorizationRequestException -> Resolution.Invalid(it.error)
                else -> throw it
            }
        })



    /**
     * Tries to validate and resolve the provided [request] into
     * a [ResolvedRequestObject]
     */
    suspend fun resolveRequest(request: AuthorizationRequest): Resolution

    companion object {

        /**
         * A factory method for obtaining an instance of [AuthorizationRequestResolver]
         * Caller should provide a http client in terms of implementing the [HttpGet]
         * interface.
         *
         * For an example implementation that uses ktor client please check [KtorAuthorizationRequestResolver]
         */
        fun make(
            getRequestObjectJwt: HttpGet<String>,
            getPresentationDefinition: HttpGet<PresentationDefinition>,
            getClientMetaData: HttpGet<ClientMetaData>,
            walletOpenId4VPConfig: WalletOpenId4VPConfig
        ): AuthorizationRequestResolver = DefaultAuthorizationRequestResolver.make(
            getRequestObjectJwt,
            getPresentationDefinition,
            getClientMetaData,
            walletOpenId4VPConfig
        )

        @Deprecated(
            "Please use ManagedAuthorizationRequestResolver",
            replaceWith = ReplaceWith("ManagedAuthorizationRequestResolver.ktor(walletOpenId4VPConfig)")
        )
        fun ktor(walletOpenId4VPConfig: WalletOpenId4VPConfig): ManagedAuthorizationRequestResolver {
            return ManagedAuthorizationRequestResolver.ktor(walletOpenId4VPConfig)
        }

    }
}

interface ManagedAuthorizationRequestResolver : AuthorizationRequestResolver, Closeable {
    companion object {
        /**
         * A factory method for obtaining an instance of [AuthorizationRequestResolver] which
         * uses the Ktor client for performing http calls
         */
        fun ktor(walletOpenId4VPConfig: WalletOpenId4VPConfig): ManagedAuthorizationRequestResolver {
            return KtorAuthorizationRequestResolver(walletOpenId4VPConfig)
        }
    }
}