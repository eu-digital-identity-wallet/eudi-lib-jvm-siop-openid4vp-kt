package eu.europa.ec.euidw.openid4vp.internal

import eu.europa.ec.euidw.openid4vp.*
import eu.europa.ec.euidw.prex.JsonParser
import eu.europa.ec.euidw.prex.PresentationDefinition
import eu.europa.ec.euidw.prex.PresentationExchange
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.decodeFromJsonElement


internal sealed interface ValidatedRequestObject {

    val clientId: String
    val clientIdScheme: ClientIdScheme?
    val clientMetaDataSource: ClientMetaDataSource?
    val nonce: String
    val responseMode: ResponseMode
    val state: String

    data class IdTokenRequestObject(
        val idTokenType: List<IdTokenType>,
        override val clientMetaDataSource: ClientMetaDataSource?,
        override val clientIdScheme: ClientIdScheme?,
        override val clientId: String,
        override val nonce: String,
        val scope: Scope,
        override val responseMode: ResponseMode,
        override val state: String
    ) : ValidatedRequestObject

    data class VpTokenRequestObject(
        val presentationDefinitionSource: PresentationDefinitionSource,
        override val clientMetaDataSource: ClientMetaDataSource?,
        override val clientIdScheme: ClientIdScheme?,
        override val clientId: String,
        override val nonce: String,
        override val responseMode: ResponseMode,
        override val state: String
    ) : ValidatedRequestObject

    data class IdAndVPTokenRequestObject(
        val idTokenType: List<IdTokenType>,
        val presentationDefinitionSource: PresentationDefinitionSource,
        override val clientMetaDataSource: ClientMetaDataSource?,
        override val clientIdScheme: ClientIdScheme?,
        override val clientId: String,
        override val nonce: String,
        val scope: Scope,
        override val responseMode: ResponseMode,
        override val state: String
    ) : ValidatedRequestObject

}


internal object RequestObjectValidator {

    private val presentationExchangeParser: JsonParser = PresentationExchange.jsonParser

    fun validate(authorizationRequest: RequestObject): Result<ValidatedRequestObject> =
        runCatching {
            fun scope() = requiredScope(authorizationRequest)
            val state = requiredState(authorizationRequest).getOrThrow()
            val nonce = requiredNonce(authorizationRequest).getOrThrow()
            val responseType = requiredResponseType(authorizationRequest).getOrThrow()
            val responseMode = requiredResponseMode(authorizationRequest).getOrThrow()
            val clientIdScheme = optionalClientIdScheme(authorizationRequest).getOrThrow()
            val clientId = requiredClientId(authorizationRequest).getOrThrow()
            val presentationDefinitionSource =
                optionalPresentationDefinitionSource(authorizationRequest, responseType) { scope().getOrNull() }
            val clientMetaDataSource = optionalClientMetaDataSource(authorizationRequest).getOrThrow()
            val idTokenType = optionalIdTokenType(authorizationRequest).getOrThrow()

            fun idAndVpToken() = ValidatedRequestObject.IdAndVPTokenRequestObject(
                idTokenType,
                presentationDefinitionSource.getOrThrow()
                    ?: throw IllegalStateException("Presentation definition missing"),
                clientMetaDataSource,
                clientIdScheme,
                clientId,
                nonce,
                scope().getOrThrow(),
                responseMode,
                state
            )

            fun idToken() = ValidatedRequestObject.IdTokenRequestObject(
                idTokenType,
                clientMetaDataSource,
                clientIdScheme,
                clientId,
                nonce,
                scope().getOrThrow(),
                responseMode,
                state
            )

            fun vpToken() = ValidatedRequestObject.VpTokenRequestObject(
                presentationDefinitionSource.getOrThrow()
                    ?: throw IllegalStateException("Presentation definition missing"),
                clientMetaDataSource,
                clientIdScheme,
                clientId,
                nonce,
                responseMode,
                state
            )

            when (responseType) {
                ResponseType.VpAndIdToken -> idAndVpToken()
                ResponseType.IdToken -> idToken()
                ResponseType.VpToken ->
                    // If scope is defined and its value is "openid" then id token must also be returned
                    if (scope().getOrNull()?.value == "openid") idAndVpToken()
                    else vpToken()
            }
        }

    private fun optionalPresentationDefinitionSource(
        authorizationRequest: RequestObject,
        responseType: ResponseType,
        scopeProvider: () -> Scope?
    ): Result<PresentationDefinitionSource?> {
        return when (responseType) {
            ResponseType.VpToken, ResponseType.VpAndIdToken ->
                parsePresentationDefinitionSource(authorizationRequest, scopeProvider.invoke())

            ResponseType.IdToken -> Result.success(null)
        }
    }


    private fun optionalIdTokenType(unvalidated: RequestObject): Result<List<IdTokenType>> = runCatching {

        unvalidated.idTokenType
            ?.split(" ")
            ?.map {
                when (it) {
                    "subject_signed_id_token" -> IdTokenType.SubjectSigned
                    "attester_signed_id_token" -> IdTokenType.AttesterSigned
                    else -> throw IllegalArgumentException("Invalid id_token_type $it")

                }
            } ?: emptyList()
    }

    private fun requiredResponseMode(unvalidated: RequestObject): Result<ResponseMode> {

        fun requiredRedirectUriAndNotProvidedResponseUri(): Result<HttpsUrl> =
            if (unvalidated.responseUri != null) RequestValidationError.ResponseUriMustNotBeProvided.asFailure()
            else when (val uri = unvalidated.redirectUri) {
                null -> RequestValidationError.MissingRedirectUri.asFailure()
                else -> HttpsUrl.make(uri).mapError { RequestValidationError.InvalidRedirectUri.asException() }
            }

        fun requiredResponseUriAndNotProvidedRedirectUri(): Result<HttpsUrl> =
            if (unvalidated.redirectUri != null) RequestValidationError.RedirectUriMustNotBeProvided.asFailure()
            else when (val uri = unvalidated.responseUri) {
                null -> RequestValidationError.MissingResponseUri.asFailure()
                else -> HttpsUrl.make(uri).mapError { RequestValidationError.InvalidResponseUri.asException() }
            }

        return when (unvalidated.responseMode) {
            "direct_post" -> requiredResponseUriAndNotProvidedRedirectUri().map { ResponseMode.DirectPost(it) }
            "direct_post.jwt" -> requiredResponseUriAndNotProvidedRedirectUri().map { ResponseMode.DirectPostJwt(it) }
            "query" -> requiredRedirectUriAndNotProvidedResponseUri().map { ResponseMode.Query(it) }
            "fragment" -> requiredRedirectUriAndNotProvidedResponseUri().map { ResponseMode.Fragment(it) }
            null -> requiredRedirectUriAndNotProvidedResponseUri().map { ResponseMode.Fragment(it) }
            else -> RequestValidationError.UnsupportedResponseMode(unvalidated.responseMode).asFailure()
        }
    }


    private fun requiredState(unvalidated: RequestObject): Result<String> =
        unvalidated.state?.success()
            ?: RequestValidationError.MissingState.asFailure()

    private fun requiredScope(unvalidated: RequestObject): Result<Scope> =
        unvalidated.scope?.let { Scope.make(it) }?.success()
            ?: RequestValidationError.MissingScope.asFailure()

    private fun requiredNonce(unvalidated: RequestObject): Result<String> =
        unvalidated.nonce?.success() ?: RequestValidationError.MissingNonce.asFailure()


    private fun requiredResponseType(unvalidated: RequestObject): Result<ResponseType> =
        when (val rt = unvalidated.responseType?.trim()) {
            "vp_token" -> ResponseType.VpToken.success()
            "vp_token id_token" -> ResponseType.VpAndIdToken.success()
            "id_token vp_token" -> ResponseType.VpAndIdToken.success()
            "id_token" -> ResponseType.IdToken.success()
            null -> RequestValidationError.MissingResponseType.asFailure()
            else -> RequestValidationError.UnsupportedResponseType(rt).asFailure()
        }


    private fun parsePresentationDefinitionSource(
        unvalidated: RequestObject,
        scope: Scope?
    ): Result<PresentationDefinitionSource> {
        val hasPd = !unvalidated.presentationDefinition.isNullOrEmpty()
        val hasPdUri = !unvalidated.presentationDefinitionUri.isNullOrEmpty()
        val hasScope = null != scope
        val json = Json { ignoreUnknownKeys = true }

        fun requiredPd() = runCatching {
            val pd = runCatching {
                json.decodeFromJsonElement<PresentationDefinition>(unvalidated.presentationDefinition!!)
            }.mapError { RequestValidationError.InvalidPresentationDefinition(it).asException() }.getOrThrow()
            PresentationDefinitionSource.PassByValue(pd)
        }


        fun requiredPdUri() = runCatching {
            val pdUri = HttpsUrl.make(unvalidated.presentationDefinitionUri!!).getOrThrow()
            PresentationDefinitionSource.FetchByReference(pdUri)
        }.mapError { RequestValidationError.InvalidPresentationDefinitionUri.asException() }

        fun requiredScope() = PresentationDefinitionSource.Implied(scope!!).success()

        return when {
            hasPd && !hasPdUri -> requiredPd()
            !hasPd && hasPdUri -> requiredPdUri()
            hasScope -> requiredScope()
            else -> RequestValidationError.MissingPresentationDefinition.asFailure()
        }
    }

    private fun optionalClientIdScheme(unvalidated: RequestObject): Result<ClientIdScheme?> =
        if (unvalidated.clientIdScheme.isNullOrEmpty()) Result.success(null)
        else ClientIdScheme.make(unvalidated.clientIdScheme)?.success()
            ?: RequestValidationError.InvalidClientIdScheme(unvalidated.clientIdScheme).asFailure()

    private fun requiredClientId(unvalidated: RequestObject): Result<String> =
        unvalidated.clientId?.success() ?: RequestValidationError.MissingClientId.asFailure()

    private fun optionalClientMetaDataSource(unvalidated: RequestObject): Result<ClientMetaDataSource?> {

        val hasCMD = !unvalidated.clientMetaData.isNullOrEmpty()
        val hasCMDUri = !unvalidated.clientMetadataUri.isNullOrEmpty()

        fun requiredClientMetaData() = runCatching {
            ClientMetaDataSource.PassByValue(Json.decodeFromJsonElement<ClientMetaData>(unvalidated.clientMetaData!!))
        }

        fun requiredClientMetaDataUri() = runCatching {
            val uri = HttpsUrl.make(unvalidated.clientMetadataUri!!)
                .mapError { RequestValidationError.InvalidClientMetaDataUri.asException() }
                .getOrThrow()
            ClientMetaDataSource.FetchByReference(uri)
        }

        return when {
            hasCMD && !hasCMDUri -> requiredClientMetaData()
            !hasCMD && hasCMDUri -> requiredClientMetaDataUri()
            hasCMD && hasCMDUri -> RequestValidationError.OneOfClientMedataOrUri.asFailure()
            else -> Result.success(null)
        }

    }

}