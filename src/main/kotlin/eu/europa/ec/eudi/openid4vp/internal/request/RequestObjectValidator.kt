/*
 * Copyright (c) 2023 European Commission
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package eu.europa.ec.eudi.openid4vp.internal.request

import eu.europa.ec.eudi.openid4vp.*
import eu.europa.ec.eudi.openid4vp.RequestValidationError.*
import eu.europa.ec.eudi.openid4vp.ResolvedRequestObject.*
import eu.europa.ec.eudi.openid4vp.dcql.DCQL
import eu.europa.ec.eudi.openid4vp.internal.ensure
import eu.europa.ec.eudi.openid4vp.internal.ensureNotNull
import eu.europa.ec.eudi.openid4vp.internal.jsonSupport
import eu.europa.ec.eudi.prex.PresentationDefinition
import kotlinx.serialization.SerializationException
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.decodeFromJsonElement
import java.net.URI
import java.net.URL

internal class RequestObjectValidator(private val siopOpenId4VPConfig: SiopOpenId4VPConfig) {

    /**
     * Validates that the given [request] represents a valid and supported [ResolvedRequestObject]
     *
     * @param request The request to validate
     * @return if given [request] is valid returns an appropriate [ResolvedRequestObject]. Otherwise,
     * raises an AuthorizationRequestException. Validation rules violations are reported using [AuthorizationRequestError]
     * wrapped inside the [specific exception][AuthorizationRequestException]
     */
    fun validateRequestObject(request: AuthenticatedRequest): ResolvedRequestObject {
        val (client, requestObject) = request
        val scope = requiredScope(requestObject)
        val nonOpenIdScope = with(Scope) { scope.getOrNull()?.items()?.filter { it != OpenId }?.mergeOrNull() }
        val state = requestObject.state
        val nonce = requiredNonce(requestObject)
        val responseType = requiredResponseType(requestObject)
        val responseMode = requiredResponseMode(client, requestObject)
        val idTokenType = optionalIdTokenType(requestObject)
        val clientMetaData = optionalClientMetaData(responseMode, requestObject)

        fun idToken(): SiopAuthentication = SiopAuthentication(
            client = client.toClient(),
            responseMode = responseMode,
            state = state,
            nonce = nonce,
            jarmRequirement = clientMetaData?.let { siopOpenId4VPConfig.jarmRequirement(it) },
            idTokenType = idTokenType,
            subjectSyntaxTypesSupported = clientMetaData?.subjectSyntaxTypesSupported.orEmpty(),
            scope = scope.getOrThrow(),
        )

        fun vpToken(): OpenId4VPAuthorization {
            val presentationQuery = requiredPresentationQuery(requestObject, nonOpenIdScope)
            val transactionData = optionalTransactionData(requestObject, presentationQuery)
            val verifierAttestations = optionalVerifierAttestations(presentationQuery, requestObject)
            return OpenId4VPAuthorization(
                client = client.toClient(),
                responseMode = responseMode,
                state = state,
                nonce = nonce,
                jarmRequirement = clientMetaData?.let { siopOpenId4VPConfig.jarmRequirement(it) },
                vpFormats = clientMetaData?.let { resolveVpFormatsCommonGround(it.vpFormats) },
                presentationQuery = presentationQuery,
                transactionData = transactionData,
                verifierAttestations = verifierAttestations,
            )
        }

        fun idAndVpToken(): SiopOpenId4VPAuthentication {
            val presentationQuery = requiredPresentationQuery(requestObject, nonOpenIdScope)
            val transactionData = optionalTransactionData(requestObject, presentationQuery)
            val verifierAttestations = optionalVerifierAttestations(presentationQuery, requestObject)
            return SiopOpenId4VPAuthentication(
                client = client.toClient(),
                responseMode = responseMode,
                state = state,
                nonce = nonce,
                jarmRequirement = clientMetaData?.let { siopOpenId4VPConfig.jarmRequirement(it) },
                vpFormats = clientMetaData?.let { resolveVpFormatsCommonGround(it.vpFormats) },
                idTokenType = idTokenType,
                subjectSyntaxTypesSupported = clientMetaData?.subjectSyntaxTypesSupported.orEmpty(),
                scope = scope.getOrThrow(),
                presentationQuery = presentationQuery,
                transactionData = transactionData,
                verifierAttestations = verifierAttestations,
            )
        }

        return when (responseType) {
            ResponseType.VpAndIdToken -> {
                if (scope.getOrNull()?.contains(Scope.OpenId) == true) idAndVpToken()
                else vpToken()
            }

            ResponseType.IdToken -> idToken()
            ResponseType.VpToken -> vpToken()
        }
    }

    /**
     * Makes sure that [unvalidated] contains a supported [PresentationDefinitionSource].
     *
     * @param unvalidated the request to validate
     */
    private fun requiredPresentationQuery(
        unvalidated: UnvalidatedRequestObject,
        scope: Scope?,
    ): PresentationQuery {
        val hasPd = !unvalidated.presentationDefinition.isNullOrEmpty()
        val hasPdUri = !unvalidated.presentationDefinitionUri.isNullOrEmpty()
        val hasDcqlQuery = !unvalidated.dcqlQuery.isNullOrEmpty()
        val hasScope = scope != null

        fun requiredPd(): PresentationQuery = try {
            checkNotNull(unvalidated.presentationDefinition)
            val pd = jsonSupport.decodeFromJsonElement<PresentationDefinition>(unvalidated.presentationDefinition)
            PresentationQuery.ByPresentationDefinition(pd)
        } catch (t: SerializationException) {
            throw InvalidPresentationDefinition(t).asException()
        }

        fun requiredDcqlQuery(): PresentationQuery = try {
            checkNotNull(unvalidated.dcqlQuery)
            val dcq = jsonSupport.decodeFromJsonElement<DCQL>(unvalidated.dcqlQuery)
            PresentationQuery.ByDigitalCredentialsQuery(dcq)
        } catch (t: SerializationException) {
            throw InvalidDigitalCredentialsQuery(t).asException()
        }

        fun requiredScope(): PresentationQuery {
            checkNotNull(scope)
            return lookupKnownPresentationDefinitionsOrDCQLQueries(scope)
        }

        val querySourceCount = listOf(hasPd, hasPdUri, hasDcqlQuery, hasScope).count { it }

        return when {
            querySourceCount > 1 -> throw MultipleQuerySources.asException()
            hasDcqlQuery -> requiredDcqlQuery()
            hasPd -> requiredPd()
            hasPdUri -> throw PresentationDefinitionByReferenceNotSupported.asException()
            hasScope -> requiredScope()
            else -> throw MissingQuerySource.asException()
        }
    }

    private fun lookupKnownPresentationDefinitionsOrDCQLQueries(scope: Scope): PresentationQuery {
        scope.items().forEach { item ->
            siopOpenId4VPConfig.vpConfiguration.knownPresentationDefinitionsPerScope[item.value]
                ?.let { return PresentationQuery.ByPresentationDefinition(it) }
        }
        scope.items().forEach { item ->
            siopOpenId4VPConfig.vpConfiguration.knownDCQLQueriesPerScope[item.value]
                ?.let { return PresentationQuery.ByDigitalCredentialsQuery(it) }
        }
        throw ResolutionError.UnknownScope(scope).asException()
    }

    private fun optionalTransactionData(
        requestObject: UnvalidatedRequestObject,
        query: PresentationQuery,
    ): List<TransactionData>? =
        requestObject.transactionData?.let { unresolvedTransactionData ->
            runCatching {
                unresolvedTransactionData.map { unresolved ->
                    TransactionData(
                        unresolved,
                        siopOpenId4VPConfig.vpConfiguration.supportedTransactionDataTypes,
                        query,
                    ).getOrThrow()
                }
            }.getOrElse { error -> throw ResolutionError.InvalidTransactionData(error).asException() }
        }

    private fun optionalVerifierAttestations(
        presentationQuery: PresentationQuery,
        unvalidated: UnvalidatedRequestObject,
    ): VerifierAttestations? =
        unvalidated.verifierAttestations
            ?.takeIf { it.isNotEmpty() }
            ?.let { array -> verifierAttestations(presentationQuery, array) }

    private fun verifierAttestations(
        query: PresentationQuery,
        verifierAttestationsArray: JsonArray,
    ): VerifierAttestations {
        fun invalid(s: String) = InvalidVerifierAttestations(s).asException()

        val attestations =
            VerifierAttestations.fromJson(verifierAttestationsArray).getOrElse { t ->
                throw invalid("Failed to deserialize verifier_attestations. Cause: ${t.message}")
            }

        when (query) {
            is PresentationQuery.ByPresentationDefinition -> {
                fun VerifierAttestations.Attestation.validQueryIds(): Boolean =
                    queryIds.isNullOrEmpty()

                ensure(attestations.value.all { a -> a.validQueryIds() }) {
                    val error =
                        "There are verifier attestations credential_id should be empty for presentation_definition queries."

                    invalid(error)
                }
            }

            is PresentationQuery.ByDigitalCredentialsQuery -> {
                val allQueryIds = query.value.credentials.map { it.id }
                fun VerifierAttestations.Attestation.validQueryIds(): Boolean =
                    if (queryIds.isNullOrEmpty()) true
                    else {
                        queryIds.all { it in allQueryIds }
                    }
                ensure(attestations.value.all { a -> a.validQueryIds() }) {
                    val error = "There are verifier attestations that use credential_id(s) not present in DCQL"
                    invalid(error)
                }
            }
        }
        return attestations
    }

    private fun resolveVpFormatsCommonGround(clientVpFormats: VpFormats): VpFormats {
        val walletSupportedVpFormats = siopOpenId4VPConfig.vpConfiguration.vpFormats
        val commonGround = VpFormats.intersect(walletSupportedVpFormats, clientVpFormats)
        return ensureNotNull(commonGround) {
            ResolutionError.ClientVpFormatsNotSupportedFromWallet.asException()
        }
    }

    private fun optionalIdTokenType(unvalidated: UnvalidatedRequestObject): List<IdTokenType> =
        unvalidated.idTokenType
            ?.trim()
            ?.split(" ")
            ?.map { type ->
                when (type) {
                    "subject_signed_id_token" -> IdTokenType.SubjectSigned
                    "attester_signed_id_token" -> IdTokenType.AttesterSigned
                    else -> error("Invalid id_token_type $type")
                }
            }
            ?: emptyList()

    private fun requiredResponseMode(
        client: AuthenticatedClient,
        unvalidated: UnvalidatedRequestObject,
    ): ResponseMode {
        fun requiredRedirectUriAndNotProvidedResponseUri(): URI {
            ensure(unvalidated.responseUri == null) { ResponseUriMustNotBeProvided.asException() }
            // Redirect URI can be omitted in case of RedirectURI
            // and use clientId instead
            val redirectUri = unvalidated.redirectUri?.asURI { InvalidRedirectUri.asException() }?.getOrThrow()
            return when (client) {
                is AuthenticatedClient.RedirectUri -> {
                    ensure(redirectUri == null || client.clientId == redirectUri) {
                        InvalidRedirectUri.asException()
                    }
                    client.clientId
                }

                else -> ensureNotNull(redirectUri) { MissingRedirectUri.asException() }
            }
        }

        fun requiredResponseUriAndNotProvidedRedirectUri(): URL {
            ensure(unvalidated.redirectUri == null) { RedirectUriMustNotBeProvided.asException() }
            val uri = unvalidated.responseUri
            ensureNotNull(uri) { MissingResponseUri.asException() }
            return uri.asURL { InvalidResponseUri.asException() }.getOrThrow()
        }

        val responseMode = when (unvalidated.responseMode) {
            "direct_post" -> requiredResponseUriAndNotProvidedRedirectUri().let { ResponseMode.DirectPost(it) }
            "direct_post.jwt" -> requiredResponseUriAndNotProvidedRedirectUri().let { ResponseMode.DirectPostJwt(it) }
            "query" -> requiredRedirectUriAndNotProvidedResponseUri().let { ResponseMode.Query(it) }
            "query.jwt" -> requiredRedirectUriAndNotProvidedResponseUri().let { ResponseMode.QueryJwt(it) }
            null, "fragment" -> requiredRedirectUriAndNotProvidedResponseUri().let { ResponseMode.Fragment(it) }
            "fragment.jwt" -> requiredRedirectUriAndNotProvidedResponseUri().let { ResponseMode.FragmentJwt(it) }
            else -> throw UnsupportedResponseMode(unvalidated.responseMode).asException()
        }

        val uri = responseMode.uri()
        when (client) {
            is AuthenticatedClient.Preregistered -> Unit
            is AuthenticatedClient.X509SanDns -> ensure(client.clientId == uri.host) {
                UnsupportedResponseMode("$responseMode host doesn't match ${client.clientId}").asException()
            }

            is AuthenticatedClient.X509SanUri -> ensure(client.clientId == uri) {
                UnsupportedResponseMode("$responseMode doesn't match ${client.clientId}").asException()
            }

            is AuthenticatedClient.RedirectUri -> ensure(client.clientId == uri) {
                UnsupportedResponseMode("$responseMode doesn't match ${client.clientId}").asException()
            }

            is AuthenticatedClient.DIDClient -> Unit

            is AuthenticatedClient.Attested -> {
                val allowedUris = when (responseMode) {
                    is ResponseMode.Query,
                    is ResponseMode.QueryJwt,
                    is ResponseMode.Fragment,
                    is ResponseMode.FragmentJwt,
                    -> client.claims.redirectUris

                    is ResponseMode.DirectPost,
                    is ResponseMode.DirectPostJwt,
                    -> client.claims.responseUris
                }
                if (!allowedUris.isNullOrEmpty()) {
                    ensure(uri.toString() in allowedUris) {
                        UnsupportedResponseMode("$responseMode use a URI that is not included in attested URIs $allowedUris").asException()
                    }
                }
            }
        }
        return responseMode
    }

    /**
     * Makes sure that [unvalidated] contains a not-null scope
     *
     * @param unvalidated the request to validate
     * @return the scope or [RequestValidationError.MissingScope]
     */
    private fun requiredScope(unvalidated: UnvalidatedRequestObject): Result<Scope> {
        val scope = unvalidated.scope?.let { Scope.make(it) }
        return if (scope != null) Result.success(scope)
        else MissingScope.asFailure()
    }

    /**
     * Makes sure that [unvalidated] contains a not-null nonce
     *
     * @param unvalidated the request to validate
     * @return the nonce or [RequestValidationError.MissingNonce]
     */
    private fun requiredNonce(unvalidated: UnvalidatedRequestObject): String =
        ensureNotNull(unvalidated.nonce) { MissingNonce.asException() }

    /**
     * Makes sure that [unvalidated] contains a supported [ResponseType].
     * Function check [UnvalidatedRequestObject.responseType]
     *
     * @param unvalidated the request to validate
     * @return the supported [ResponseType], or [RequestValidationError.MissingResponseType] if the response type is not provided
     * or [RequestValidationError.UnsupportedResponseType] if the response type is not supported
     */
    private fun requiredResponseType(unvalidated: UnvalidatedRequestObject): ResponseType =
        when (val rt = unvalidated.responseType?.trim()) {
            "vp_token" -> ResponseType.VpToken
            "vp_token id_token", "id_token vp_token" -> ResponseType.VpAndIdToken
            "id_token" -> ResponseType.IdToken
            null -> throw MissingResponseType.asException()
            else -> throw UnsupportedResponseType(rt).asException()
        }

    private fun optionalClientMetaData(
        responseMode: ResponseMode,
        unvalidated: UnvalidatedRequestObject,
    ): ValidatedClientMetaData? {
        val hasCMD = !unvalidated.clientMetaData.isNullOrEmpty()

        fun requiredClientMetaData(): UnvalidatedClientMetaData {
            checkNotNull(unvalidated.clientMetaData)
            return jsonSupport.decodeFromJsonElement(unvalidated.clientMetaData)
        }

        fun required() = when (responseMode) {
            is ResponseMode.DirectPost -> false
            is ResponseMode.DirectPostJwt -> true
            is ResponseMode.Fragment -> false
            is ResponseMode.FragmentJwt -> true
            is ResponseMode.Query -> false
            is ResponseMode.QueryJwt -> true
        }

        return when {
            hasCMD -> requiredClientMetaData().let {
                ClientMetaDataValidator.validateClientMetaData(it, responseMode)
            }
            else -> {
                ensure(!required()) {
                    InvalidClientMetaData("Missing client metadata").asException()
                }
                null
            }
        }
    }
}

private fun AuthenticatedClient.toClient(): Client =
    when (this) {
        is AuthenticatedClient.Preregistered -> Client.Preregistered(
            preregisteredClient.clientId,
            preregisteredClient.legalName,
        )

        is AuthenticatedClient.RedirectUri -> Client.RedirectUri(clientId)
        is AuthenticatedClient.X509SanDns -> Client.X509SanDns(clientId, chain[0])
        is AuthenticatedClient.X509SanUri -> Client.X509SanUri(clientId, chain[0])
        is AuthenticatedClient.DIDClient -> Client.DIDClient(client.uri)
        is AuthenticatedClient.Attested -> Client.Attested(clientId)
    }

private fun ResponseMode.uri(): URI = when (this) {
    is ResponseMode.DirectPost -> responseURI.toURI()
    is ResponseMode.DirectPostJwt -> responseURI.toURI()
    is ResponseMode.Fragment -> redirectUri
    is ResponseMode.FragmentJwt -> redirectUri
    is ResponseMode.Query -> redirectUri
    is ResponseMode.QueryJwt -> redirectUri
}

private enum class ResponseType {
    VpToken,
    IdToken,
    VpAndIdToken,
}
