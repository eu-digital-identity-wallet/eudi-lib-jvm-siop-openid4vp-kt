package eu.europa.ec.euidw.openid4vp.internal

import eu.europa.ec.euidw.openid4vp.*
import eu.europa.ec.euidw.openid4vp.internal.utils.HttpsUrl
import eu.europa.ec.euidw.openid4vp.internal.utils.mapError
import eu.europa.ec.euidw.openid4vp.internal.utils.success
import eu.europa.ec.euidw.prex.JsonParser
import eu.europa.ec.euidw.prex.PresentationExchange
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.decodeFromJsonElement
import kotlinx.serialization.json.jsonObject
import java.net.URLDecoder


sealed interface ValidatedSiopId4VPRequestObject {

    data class IdTokenRequestObject(
        val idTokenType: List<IdTokenType>,
        val clientMetaDataSource: ClientMetaDataSource?,
        val clientIdScheme: ClientIdScheme?,
        val clientId: String,
        val nonce: String,
        val scope: Scope?,
        val responseMode: ResponseMode,
        val state: String?
    ) : ValidatedSiopId4VPRequestObject

    data class VpTokenRequestObject(
        val presentationDefinitionSource: PresentationDefinitionSource,
        val clientMetaDataSource: ClientMetaDataSource?,
        val clientIdScheme: ClientIdScheme?,
        val clientId: String,
        val nonce: String,
        val responseMode: ResponseMode,
        val state: String?
    ) : ValidatedSiopId4VPRequestObject

    data class IdAndVPTokenRequestObject(
        val idTokenType: List<IdTokenType>,
        val presentationDefinitionSource: PresentationDefinitionSource,
        val clientMetaDataSource: ClientMetaDataSource?,
        val clientIdScheme: ClientIdScheme?,
        val clientId: String,
        val nonce: String,
        val scope: Scope?,
        val responseMode: ResponseMode,
        val state: String?
    ) : ValidatedSiopId4VPRequestObject

}


object SiopId4VPRequestValidator{

    private val presentationExchangeParser: JsonParser = PresentationExchange.jsonParser

    fun validate(authorizationRequest: SiopId4VPRequestObject): Result<ValidatedSiopId4VPRequestObject> =
        runCatching {
            val scope = authorizationRequest.scope?.let { Scope.make(it) }
            val nonce = requiredNonce(authorizationRequest).getOrThrow()
            val responseType = requiredResponseType(authorizationRequest).getOrThrow()
            val responseMode = requiredResponseMode(authorizationRequest).getOrThrow()
            val clientIdScheme = optionalClientIdScheme(authorizationRequest).getOrThrow()
            val clientId = requiredClientId(authorizationRequest).getOrThrow()
            val presentationDefinitionSource = optionalPresentationDefinitionSource(authorizationRequest, responseType, scope)
            val clientMetaDataSource = optionalClientMetaDataSource(authorizationRequest).getOrThrow()
            val idTokenType = optionalIdTokenType(authorizationRequest).getOrThrow()

            fun idAndVpToken() = ValidatedSiopId4VPRequestObject.IdAndVPTokenRequestObject(
                idTokenType,
                presentationDefinitionSource.getOrThrow() ?: throw IllegalStateException("Presentation definition missing"),
                clientMetaDataSource,
                clientIdScheme,
                clientId,
                nonce,
                scope,
                responseMode,
                state = null
            )

            fun idToken() = ValidatedSiopId4VPRequestObject.IdTokenRequestObject(
                idTokenType,
                clientMetaDataSource,
                clientIdScheme,
                clientId,
                nonce,
                scope,
                responseMode,
                state = null
            )

            fun vpToken() = ValidatedSiopId4VPRequestObject.VpTokenRequestObject(
                presentationDefinitionSource.getOrThrow() ?: throw IllegalStateException("Presentation definition missing"),
                clientMetaDataSource,
                clientIdScheme,
                clientId,
                nonce,
                responseMode,
                state = null
            )

            when (responseType) {
                ResponseType.VpAndIdToken -> idAndVpToken()
                ResponseType.IdToken -> idToken()
                ResponseType.VpToken ->
                    // If scope is defined and its value is "openid" then id token must also be returned
                    if (scope?.value == "openid") idAndVpToken()
                    else vpToken()
            }
        }

    private fun optionalPresentationDefinitionSource(
        authorizationRequest: SiopId4VPRequestObject,
        responseType: ResponseType,
        scope: Scope?
    ): Result<PresentationDefinitionSource?> {
        return when  {
            responseType == ResponseType.VpToken || responseType == ResponseType.VpAndIdToken ->
                parsePresentationDefinitionSource(authorizationRequest, scope)
            else -> Result.success(null)
        }
    }


    private fun optionalIdTokenType(unvalidated: SiopId4VPRequestObject): Result<List<IdTokenType>> = runCatching {

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

    private fun requiredResponseMode(unvalidated: SiopId4VPRequestObject): Result<ResponseMode> {

        fun requiredRedirectUriAndNotProvidedResponseUri(): Result<HttpsUrl> =
            if (unvalidated.responseUri != null) SiopId4VPRequestValidationError.ResponseUriMustNotBeProvided.asFailure()
            else when (val uri = unvalidated.redirectUri) {
                null -> SiopId4VPRequestValidationError.MissingRedirectUri.asFailure()
                else -> HttpsUrl.make(uri).mapError { SiopId4VPRequestValidationError.InvalidRedirectUri.asException() }
            }

        fun requiredResponseUriAndNotProvidedRedirectUri(): Result<HttpsUrl> =
            if (unvalidated.redirectUri != null) SiopId4VPRequestValidationError.RedirectUriMustNotBeProvided.asFailure()
            else when (val uri = unvalidated.responseUri) {
                null -> SiopId4VPRequestValidationError.MissingResponseUri.asFailure()
                else -> HttpsUrl.make(uri).mapError { SiopId4VPRequestValidationError.InvalidResponseUri.asException() }
            }

        return when (unvalidated.responseMode) {
            "direct_post" -> requiredResponseUriAndNotProvidedRedirectUri().map { ResponseMode.DirectPost(it) }
            "direct_post.jwt" -> requiredResponseUriAndNotProvidedRedirectUri().map { ResponseMode.DirectPostJwt(it) }
            "query" -> requiredRedirectUriAndNotProvidedResponseUri().map { ResponseMode.Query(it) }
            "fragment" -> requiredRedirectUriAndNotProvidedResponseUri().map { ResponseMode.Fragment(it) }
            null -> requiredRedirectUriAndNotProvidedResponseUri().map { ResponseMode.Fragment(it) }
            else -> SiopId4VPRequestValidationError.UnsupportedResponseMode(unvalidated.responseMode).asFailure()
        }
    }


    private fun requiredNonce(unvalidated: SiopId4VPRequestObject): Result<String> =
        unvalidated.nonce?.success() ?: SiopId4VPRequestValidationError.MissingNonce.asFailure()


    private fun requiredResponseType(unvalidated: SiopId4VPRequestObject): Result<ResponseType> =
        when (val rt = unvalidated.responseType?.trim()) {
            "vp_token" -> ResponseType.VpToken.success()
            "vp_token id_token"  -> ResponseType.VpAndIdToken.success()
            "id_token vp_token"  -> ResponseType.VpAndIdToken.success()
            "id_token" -> ResponseType.IdToken.success()
            null -> SiopId4VPRequestValidationError.MissingResponseType.asFailure()
            else -> SiopId4VPRequestValidationError.UnsupportedResponseType(rt).asFailure()
        }


    private fun parsePresentationDefinitionSource(
        unvalidated: SiopId4VPRequestObject,
        scope: Scope?
    ): Result<PresentationDefinitionSource> {
        val hasPd = !unvalidated.presentationDefinition.isNullOrEmpty()
        val hasPdUri = !unvalidated.presentationDefinitionUri.isNullOrEmpty()
        val hasScope = null != scope

        fun requiredPd() = runCatching {
            val pd = presentationExchangeParser.decodePresentationDefinition(
                unvalidated.presentationDefinition!!
            ).mapError { SiopId4VPRequestValidationError.InvalidPresentationDefinition(it).asException() }.getOrThrow()
            PresentationDefinitionSource.PassByValue(pd)
        }


        fun requiredPdUri() = runCatching {
            val pdUri = HttpsUrl.make(unvalidated.presentationDefinitionUri!!).getOrThrow()
            PresentationDefinitionSource.FetchByReference(pdUri)
        }.mapError { SiopId4VPRequestValidationError.InvalidPresentationDefinitionUri.asException() }

        fun requiredScope() = PresentationDefinitionSource.Implied(scope!!).success()

        return when {
            hasPd && !hasPdUri -> requiredPd()
            !hasPd && hasPdUri -> requiredPdUri()
            hasScope -> requiredScope()
            else -> SiopId4VPRequestValidationError.MissingPresentationDefinition.asFailure()
        }
    }

    private fun optionalClientIdScheme(unvalidated: SiopId4VPRequestObject): Result<ClientIdScheme?> =
        if (unvalidated.clientIdScheme.isNullOrEmpty()) Result.success(null)
        else ClientIdScheme.make(unvalidated.clientIdScheme)?.success()
            ?: SiopId4VPRequestValidationError.InvalidClientIdScheme(unvalidated.clientIdScheme).asFailure()

    private fun requiredClientId(unvalidated: SiopId4VPRequestObject): Result<String> =
        unvalidated.clientId?.success() ?: SiopId4VPRequestValidationError.MissingClientId.asFailure()

    private fun optionalClientMetaDataSource(unvalidated: SiopId4VPRequestObject): Result<ClientMetaDataSource?> {

        val hasCMD = !unvalidated.clientMetaData.isNullOrEmpty()
        val hasCMDUri = !unvalidated.clientMetadataUri.isNullOrEmpty()

        fun requiredClientMetaData() = runCatching {
            val decoded = URLDecoder.decode(unvalidated.clientMetaData, "UTF-8")
            val j = Json.parseToJsonElement(decoded).jsonObject
            ClientMetaDataSource.PassByValue(Json.decodeFromJsonElement<ClientMetaData>(j))
        }

        fun requiredClientMetaDataUri() = runCatching {
            val uri = HttpsUrl.make(unvalidated.clientMetadataUri!!)
                .mapError { SiopId4VPRequestValidationError.InvalidClientMetaDataUri.asException() }
                .getOrThrow()
            ClientMetaDataSource.FetchByReference(uri)
        }

        return when {
            hasCMD && !hasCMDUri -> requiredClientMetaData()
            !hasCMD && hasCMDUri -> requiredClientMetaDataUri()
            hasCMD && hasCMDUri -> SiopId4VPRequestValidationError.OneOfClientMedataOrUri.asFailure()
            else -> Result.success(null)
        }

    }

}