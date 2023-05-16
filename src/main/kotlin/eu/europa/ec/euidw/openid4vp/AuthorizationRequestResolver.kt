package eu.europa.ec.euidw.openid4vp

import com.eygraber.uri.Uri
import com.nimbusds.openid.connect.sdk.rp.OIDCClientMetadata
import eu.europa.ec.euidw.openid4vp.AuthorizationRequest.JwtSecured.PassByReference
import eu.europa.ec.euidw.openid4vp.AuthorizationRequest.JwtSecured.PassByValue
import eu.europa.ec.euidw.openid4vp.ResolvedRequestObject.OpenId4VPAuthorization
import eu.europa.ec.euidw.openid4vp.ResolvedRequestObject.SiopOpenId4VPAuthentication
import eu.europa.ec.euidw.openid4vp.internal.ktor.KtorAuthorizationRequestResolver
import eu.europa.ec.euidw.openid4vp.internal.request.DefaultAuthorizationRequestResolver
import eu.europa.ec.euidw.prex.PresentationDefinition
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.jsonObject
import java.io.Closeable
import java.io.Serializable
import java.net.URL

/**
 * OAUTH2 authorization request
 *
 * This is merely a data carrier structure which doesn't enforce any rules.
 */
sealed interface AuthorizationRequest : Serializable {

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
        data class PassByReference(override val clientId: String, val jwtURI: URL) : JwtSecured
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
                !requestUriValue.isNullOrEmpty() ->requestUriValue.asURL().map { PassByReference(clientId(), it) }.getOrThrow()

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
sealed interface ResolvedRequestObject : Serializable {

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

/**
 * Errors that can occur while validating & resolving
 * an [AuthorizationRequest]
 */
sealed interface AuthorizationRequestError : Serializable

/**
 * Validation errors that can occur while validating
 * an [AuthorizationRequest]
 */
sealed interface RequestValidationError : AuthorizationRequestError {

    //
    // Response Type errors
    //
    data class UnsupportedResponseType(val value: String) : RequestValidationError
    object MissingResponseType : RequestValidationError {
        override fun toString(): String = "MissingResponseType"
    }

    //
    // Response Mode errors
    //
    data class UnsupportedResponseMode(val value: String?) : RequestValidationError

    //
    // Presentation Definition errors
    //
    object MissingPresentationDefinition : RequestValidationError {
        override fun toString(): String = "MissingPresentationDefinition"
    }

    data class InvalidPresentationDefinition(val cause: Throwable) : RequestValidationError
    object InvalidPresentationDefinitionUri : RequestValidationError {
        override fun toString(): String = "InvalidPresentationDefinitionUri"
    }

    object InvalidRedirectUri : RequestValidationError {
        override fun toString(): String = "InvalidRedirectUri"
    }

    object MissingRedirectUri : RequestValidationError {
        override fun toString(): String = "MissingRedirectUri"
    }

    object MissingResponseUri : RequestValidationError {
        override fun toString(): String = "MissingResponseUri"
    }

    object InvalidResponseUri : RequestValidationError {
        override fun toString(): String = "InvalidResponseUri"
    }

    object ResponseUriMustNotBeProvided : RequestValidationError {
        override fun toString(): String = "ResponseUriMustNotBeProvided"
    }

    object RedirectUriMustNotBeProvided : RequestValidationError {
        override fun toString(): String = "RedirectUriMustNotBeProvided"
    }

    object MissingState : RequestValidationError {
        override fun toString(): String = "MissingState"
    }

    object MissingNonce : RequestValidationError {
        override fun toString(): String = "MissingNonce"
    }

    object MissingScope : RequestValidationError {
        override fun toString(): String = "MissingScope"
    }

    object MissingClientId : RequestValidationError {
        override fun toString(): String = "MissingClientId"
    }

    object InvalidClientMetaDataUri : RequestValidationError {
        override fun toString(): String = "InvalidClientMetaDataUri"
    }

    object OneOfClientMedataOrUri : RequestValidationError {
        override fun toString(): String = "OneOfClientMedataOrUri"
    }

    object SubjectSyntaxTypesNoMatch : RequestValidationError {
        override fun toString(): String = "SubjectSyntaxTypesNoMatch"
    }

    object MissingClientMetadataJwksSource : RequestValidationError {
        override fun toString(): String = "MissingClientMetadataJwksSource"
    }

    object BothJwkUriAndInlineJwks : RequestValidationError {
        override fun toString(): String = "BothJwkUriAndInlineJwks"
    }

    object SubjectSyntaxTypesWrongSyntax : RequestValidationError {
        override fun toString(): String = "SubjectSyntaxTypesWrongSyntax"
    }

    data class InvalidClientIdScheme(val value: String) : RequestValidationError

}

/**
 * Errors that can occur while resolving an [AuthorizationRequest]
 */
sealed interface ResolutionError : AuthorizationRequestError {
    data class PresentationDefinitionNotFoundForScope(val scope: Scope) : ResolutionError
    object FetchingPresentationDefinitionNotSupported : ResolutionError
    data class UnableToFetchPresentationDefinition(val cause: Throwable) : ResolutionError
    data class UnableToFetchClientMetadata(val cause: Throwable) : ResolutionError
    data class UnableToFetchRequestObject(val cause: Throwable) : ResolutionError
    data class ClientMetadataJwkUriUnparsable(val cause: Throwable) : ResolutionError
    data class ClientMetadataJwkResolutionFailed(val cause: Throwable) : ResolutionError
}

/**
 * An exception indicating an expected [error] while validating and/or resolving
 * an [AuthorizationRequest]
 */
data class AuthorizationRequestException(val error: AuthorizationRequestError) : RuntimeException()

/**
 * Convenient method that lifts an [AuthorizationRequestError] into
 * a [AuthorizationRequestException]
 */
fun AuthorizationRequestError.asException(): AuthorizationRequestException =
    AuthorizationRequestException(this)


/**
 * Convenient method that lifts an [AuthorizationRequestError] into
 * [Result] context (wrapping an [AuthorizationRequestException])
 */
fun <T> AuthorizationRequestError.asFailure(): Result<T> =
    Result.failure(asException())

/**
 * The outcome of [validating & resolving][AuthorizationRequestResolver.resolveRequestUri]
 * an [AuthorizationRequest].
 */
sealed interface Resolution {
    /**
     * Represents the success of validating & resolving an [AuthorizationRequest]
     * into a [requestObject]
     */
    data class Success(val requestObject: ResolvedRequestObject) : Resolution

    /**
     * Represents the failure of validating or resolving an [AuthorizationRequest]
     * due to [error]
     */
    data class Invalid(val error: AuthorizationRequestError) : Resolution
}

/**
 * An interface that describes a service
 * that accepts an [authorization request][AuthorizationRequest], validates it and resolves it (that is
 * fetches parts of the authorization request that are provided by reference)
 *
 */
fun interface AuthorizationRequestResolver {

    /**
     * Tries to validate and request the provided [uri] into
     * a [ResolvedRequestObject]
     */
    suspend fun resolveRequestUri(uri: String): Resolution = AuthorizationRequest.make(uri).fold(
        onSuccess = { request -> resolveRequest(request) },
        onFailure = { throwable ->
            if (throwable is AuthorizationRequestException) Resolution.Invalid(throwable.error)
            else throw throwable
        })


    /**
     * Tries to validate and request the provided [request] into
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