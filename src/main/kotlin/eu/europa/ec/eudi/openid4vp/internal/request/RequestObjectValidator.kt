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
import kotlinx.serialization.SerializationException
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

        fun idToken(): SiopAuthentication {
            val clientMetaData = optionalClientMetaData(responseMode, null, requestObject)
            return SiopAuthentication(
                client = client.toClient(),
                responseMode = responseMode,
                state = state,
                nonce = nonce,
                responseEncryptionSpecification = clientMetaData?.responseEncryptionSpecification,
                idTokenType = idTokenType,
                subjectSyntaxTypesSupported = clientMetaData?.subjectSyntaxTypesSupported.orEmpty(),
                scope = scope.getOrThrow(),
            )
        }

        fun vpToken(): OpenId4VPAuthorization {
            val query = requiredDcqlQuery(requestObject, nonOpenIdScope, siopOpenId4VPConfig.vpConfiguration.vpFormatsSupported)
            val transactionData = optionalTransactionData(requestObject, query)
            val verifierInfo = optionalVerifierInfo(query, requestObject)
            val clientMetaData = optionalClientMetaData(responseMode, query, requestObject)
            return OpenId4VPAuthorization(
                client = client.toClient(),
                responseMode = responseMode,
                state = state,
                nonce = nonce,
                responseEncryptionSpecification = clientMetaData?.responseEncryptionSpecification,
                vpFormatsSupported = clientMetaData?.vpFormatsSupported,
                query = query,
                transactionData = transactionData,
                verifierInfo = verifierInfo,
            )
        }

        fun idAndVpToken(): SiopOpenId4VPAuthentication {
            val query = requiredDcqlQuery(requestObject, nonOpenIdScope, siopOpenId4VPConfig.vpConfiguration.vpFormatsSupported)
            val transactionData = optionalTransactionData(requestObject, query)
            val verifierInfo = optionalVerifierInfo(query, requestObject)
            val clientMetaData = optionalClientMetaData(responseMode, query, requestObject)
            return SiopOpenId4VPAuthentication(
                client = client.toClient(),
                responseMode = responseMode,
                state = state,
                nonce = nonce,
                responseEncryptionSpecification = clientMetaData?.responseEncryptionSpecification,
                vpFormatsSupported = clientMetaData?.vpFormatsSupported,
                idTokenType = idTokenType,
                subjectSyntaxTypesSupported = clientMetaData?.subjectSyntaxTypesSupported.orEmpty(),
                scope = scope.getOrThrow(),
                query = query,
                transactionData = transactionData,
                verifierInfo = verifierInfo,
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
     * Makes sure that [unvalidated] contains a [DCQL] query with [Format] the Wallet supports.
     *
     * @param unvalidated the request to validate
     * @param walletSupportsVpFormats the [VpFormatsSupported] supported by the Wallet
     */
    private fun requiredDcqlQuery(
        unvalidated: UnvalidatedRequestObject,
        scope: Scope?,
        walletSupportsVpFormats: VpFormatsSupported,
    ): DCQL {
        val hasDcqlQuery = !unvalidated.dcqlQuery.isNullOrEmpty()
        val hasScope = scope != null

        fun requiredDcqlQuery(): DCQL = try {
            checkNotNull(unvalidated.dcqlQuery)
            jsonSupport.decodeFromJsonElement<DCQL>(unvalidated.dcqlQuery)
        } catch (t: SerializationException) {
            throw InvalidDigitalCredentialsQuery(t).asException()
        }

        fun requiredScope(): DCQL {
            checkNotNull(scope)
            return lookupKnownDCQLQueries(scope)
        }

        val querySourceCount = listOf(hasDcqlQuery, hasScope).count { it }

        val query = when {
            querySourceCount > 1 -> throw MultipleQuerySources.asException()
            hasDcqlQuery -> requiredDcqlQuery()
            hasScope -> requiredScope()
            else -> throw MissingQuerySource.asException()
        }

        val queryFormats = query.credentials.value.map { it.format }.toSet()
        ensure(walletSupportsVpFormats.containsAll(queryFormats)) {
            UnsupportedQueryFormats.asException()
        }

        return query
    }

    private fun lookupKnownDCQLQueries(scope: Scope): DCQL {
        scope.items().forEach { item ->
            siopOpenId4VPConfig.vpConfiguration.knownDCQLQueriesPerScope[item.value]
                ?.let { return it }
        }
        throw ResolutionError.UnknownScope(scope).asException()
    }

    private fun optionalTransactionData(
        requestObject: UnvalidatedRequestObject,
        query: DCQL,
    ): List<TransactionData>? =
        requestObject.transactionData?.let { unresolvedTransactionData ->
            runCatching {
                unresolvedTransactionData.values.map { unresolved ->
                    TransactionData.parse(
                        unresolved,
                        siopOpenId4VPConfig.vpConfiguration.supportedTransactionDataTypes,
                        query,
                    ).getOrThrow()
                }
            }.getOrElse { error -> throw ResolutionError.InvalidTransactionData(error).asException() }
        }

    private fun optionalVerifierInfo(
        query: DCQL,
        unvalidated: UnvalidatedRequestObject,
    ): VerifierInfo? = unvalidated.verifierInfo?.let { verifierInfo(query, it) }

    private fun verifierInfo(
        query: DCQL,
        unvalidated: VerifierInfoTO,
    ): VerifierInfo {
        fun invalid(reason: String) = InvalidVerifierInfo(reason).asException()

        val verifierInfo =
            VerifierInfo.fromJson(unvalidated.value).getOrElse { error ->
                throw invalid("Failed to deserialize ${OpenId4VPSpec.VERIFIER_INFO}. Cause: ${error.message}")
            }

        fun VerifierInfo.validQueryIds(): Boolean =
            attestations.all { attestation -> attestation.credentialIds?.unknownIds(query.credentials).isNullOrEmpty() }

        ensure(verifierInfo.validQueryIds()) {
            val error = "There are verifier attestations that use credential_id(s) not present in DCQL"
            invalid(error)
        }

        return verifierInfo
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

            is AuthenticatedClient.RedirectUri -> ensure(client.clientId == uri) {
                UnsupportedResponseMode("$responseMode doesn't match ${client.clientId}").asException()
            }

            is AuthenticatedClient.DecentralizedIdentifier -> Unit

            is AuthenticatedClient.VerifierAttestation -> {
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

            is AuthenticatedClient.X509SanDns -> ensure(client.clientId == uri.host) {
                UnsupportedResponseMode("$responseMode host doesn't match ${client.clientId}").asException()
            }

            is AuthenticatedClient.X509Hash -> Unit
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
        query: DCQL?,
        unvalidated: UnvalidatedRequestObject,
    ): ValidatedClientMetaData? {
        val hasCMD = !unvalidated.clientMetaData.isNullOrEmpty()

        fun requiredClientMetaData(): UnvalidatedClientMetaData {
            checkNotNull(unvalidated.clientMetaData)
            return jsonSupport.decodeFromJsonElement(unvalidated.clientMetaData)
        }

        return when {
            hasCMD -> requiredClientMetaData().let {
                ClientMetaDataValidator.validateClientMetaData(
                    it,
                    responseMode,
                    query,
                    siopOpenId4VPConfig.responseEncryptionConfiguration,
                    siopOpenId4VPConfig.vpConfiguration.vpFormatsSupported,
                )
            }

            else -> {
                ensure(!responseMode.requiresEncryption()) {
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
        is AuthenticatedClient.DecentralizedIdentifier -> Client.DecentralizedIdentifier(client.uri)
        is AuthenticatedClient.VerifierAttestation -> Client.VerifierAttestation(clientId)
        is AuthenticatedClient.X509SanDns -> Client.X509SanDns(clientId, chain[0])
        is AuthenticatedClient.X509Hash -> Client.X509Hash(clientId, chain[0])
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
