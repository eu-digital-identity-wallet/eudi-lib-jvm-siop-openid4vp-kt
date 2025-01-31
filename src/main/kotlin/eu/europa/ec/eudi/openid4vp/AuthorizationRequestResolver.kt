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
package eu.europa.ec.eudi.openid4vp

import com.nimbusds.jose.util.Base64URL
import eu.europa.ec.eudi.openid4vp.Client.*
import eu.europa.ec.eudi.openid4vp.ResolvedRequestObject.OpenId4VPAuthorization
import eu.europa.ec.eudi.openid4vp.ResolvedRequestObject.SiopOpenId4VPAuthentication
import eu.europa.ec.eudi.openid4vp.dcql.DCQL
import eu.europa.ec.eudi.openid4vp.internal.*
import eu.europa.ec.eudi.openid4vp.internal.request.RequestUriMethod
import eu.europa.ec.eudi.prex.PresentationDefinition
import kotlinx.io.bytestring.decodeToByteString
import kotlinx.io.bytestring.decodeToString
import kotlinx.serialization.DeserializationStrategy
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.serializer
import org.bouncycastle.asn1.x500.X500Name
import org.bouncycastle.asn1.x500.style.BCStyle
import java.io.Serializable
import java.net.URI
import java.security.cert.X509Certificate

/**
 * Represents an OAuth2 RP that submitted an Authorization Request.
 */
sealed interface Client : Serializable {

    data class Preregistered(val clientId: OriginalClientId, val legalName: String) : Client
    data class RedirectUri(val clientId: URI) : Client
    data class X509SanDns(val clientId: OriginalClientId, val cert: X509Certificate) : Client
    data class X509SanUri(val clientId: URI, val cert: X509Certificate) : Client
    data class DIDClient(val clientId: URI) : Client
    data class Attested(val clientId: OriginalClientId) : Client

    /**
     * The id of the client prefixed with the client id scheme.
     */
    val id: VerifierId
        get() = when (this) {
            is Preregistered -> VerifierId(ClientIdScheme.PreRegistered, clientId)
            is RedirectUri -> VerifierId(ClientIdScheme.RedirectUri, clientId.toString())
            is X509SanDns -> VerifierId(ClientIdScheme.X509_SAN_DNS, clientId)
            is X509SanUri -> VerifierId(ClientIdScheme.X509_SAN_URI, clientId.toString())
            is DIDClient -> VerifierId(ClientIdScheme.DID, clientId.toString())
            is Attested -> VerifierId(ClientIdScheme.VERIFIER_ATTESTATION, clientId)
        }
}

/**
 * Gets the legal name (i.e., CN) from this [X509Certificate].
 */
fun X509Certificate.legalName(): String? {
    val distinguishedName = X500Name(subjectX500Principal.name)
    val commonNames = distinguishedName.getRDNs(BCStyle.CN).orEmpty().toList()
        .flatMap { it.typesAndValues.orEmpty().toList() }
        .map { it.value.toString() }
    return commonNames.firstOrNull { it.isNotBlank() }
}

/**
 * Gets the legal name of this [Client].
 *
 * @param legalName a function to extract a legal name from a [X509Certificate]. Defaults to [X509Certificate.legalName].
 */
fun Client.legalName(legalName: X509Certificate.() -> String? = X509Certificate::legalName): String? {
    return when (this) {
        is Preregistered -> this.legalName
        is RedirectUri -> null
        is X509SanDns -> cert.legalName()
        is X509SanUri -> cert.legalName()
        is DIDClient -> null
        is Attested -> null
    }
}

/**
 * Represents resolved (i.e. supported by the Wallet) Transaction Data.
 *
 * @property value the original Base64Url encoded value as provided by the Verifier, over which the Transaction Data Hash will be calculated
 * @property jsonObject this Transaction Data as a generic JsonObject
 * @property type the type of the Transaction Data
 * @property credentialIds identifiers of the requested Credentials this Transaction Data is applicable to
 * @property hashAlgorithms Hash Algorithms with which the Hash of this Transaction Data can be calculated
 */
data class TransactionData private constructor(val value: Base64URL) : Serializable {
    init {
        require(value.toString().isNotBlank())
    }

    val jsonObject: JsonObject by lazy {
        val decoded = base64UrlNoPadding.decodeToByteString(value.toString())
        jsonSupport.decodeFromString(decoded.decodeToString())
    }

    val type: TransactionDataType
        get() = TransactionDataType(jsonObject.requiredString(OpenId4VPSpec.TRANSACTION_DATA_TYPE))

    val credentialIds: List<TransactionDataCredentialId>
        get() = jsonObject.requiredStringArray(OpenId4VPSpec.TRANSACTION_DATA_CREDENTIAL_IDS)
            .map { TransactionDataCredentialId(it) }

    val hashAlgorithms: List<HashAlgorithm>
        get() = jsonObject.optionalStringArray(OpenId4VPSpec.TRANSACTION_DATA_HASH_ALGORITHMS)
            ?.map { HashAlgorithm(it) }
            ?: listOf(HashAlgorithm.SHA_256)

    /**
     * Converts this Transaction Data to an instance of [T].
     */
    inline fun <reified T> decode(
        deserializer: DeserializationStrategy<T> = serializer(),
        json: Json = Json.Default,
    ): T = json.decodeFromJsonElement(deserializer, jsonObject)

    companion object {
        internal operator fun invoke(
            value: String,
            supportedTypes: List<SupportedTransactionDataType>,
            query: PresentationQuery,
        ): Result<TransactionData> = runCatching {
            val decoded = base64UrlNoPadding.decodeToByteString(value)
            val deserialized = jsonSupport.decodeFromString<JsonObject>(decoded.decodeToString())

            val type = TransactionDataType(deserialized.requiredString(OpenId4VPSpec.TRANSACTION_DATA_TYPE))
            val supportedType = supportedTypes.firstOrNull { it.type == type }
            requireNotNull(supportedType) { "Unsupported '${OpenId4VPSpec.TRANSACTION_DATA_TYPE}': '$type'" }

            val requestedCredentialIds = when (query) {
                is PresentationQuery.ByPresentationDefinition -> query.value.inputDescriptors.map {
                    TransactionDataCredentialId(
                        it.id.value,
                    )
                }
                is PresentationQuery.ByDigitalCredentialsQuery -> query.value.credentials.map { TransactionDataCredentialId(it.id.value) }
            }
            val credentialIds = deserialized.requiredStringArray(OpenId4VPSpec.TRANSACTION_DATA_CREDENTIAL_IDS)
                .map { TransactionDataCredentialId(it) }
            require(requestedCredentialIds.containsAll(credentialIds)) {
                "Invalid '${OpenId4VPSpec.TRANSACTION_DATA_CREDENTIAL_IDS}': '$credentialIds'"
            }

            val supportedHashAlgorithms = supportedType.hashAlgorithms
            val hashAlgorithms = deserialized.optionalStringArray(OpenId4VPSpec.TRANSACTION_DATA_HASH_ALGORITHMS)
                ?.map { HashAlgorithm(it) }
                ?.toSet()
                ?: setOf(HashAlgorithm.SHA_256)
            require(supportedHashAlgorithms.intersect(hashAlgorithms).isNotEmpty()) {
                "Unsupported '${OpenId4VPSpec.TRANSACTION_DATA_HASH_ALGORITHMS}': '$hashAlgorithms'"
            }

            TransactionData(Base64URL.from(value))
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

    val client: Client
    val responseMode: ResponseMode
    val state: String?
    val nonce: String

    /**
     * The verifier's requirements, if any, for encrypting and/or signing the authorization
     * response using JARM.
     */
    val jarmRequirement: JarmRequirement?

    /**
     * SIOPv2 Authentication request for issuing an id_token
     */
    data class SiopAuthentication(
        override val client: Client,
        override val responseMode: ResponseMode,
        override val state: String?,
        override val nonce: String,
        override val jarmRequirement: JarmRequirement?,
        val idTokenType: List<IdTokenType>,
        val subjectSyntaxTypesSupported: List<SubjectSyntaxType>,
        val scope: Scope,
    ) : ResolvedRequestObject

    /**
     * OpenId4VP Authorization request for presenting a vp_token
     */
    data class OpenId4VPAuthorization(
        override val client: Client,
        override val responseMode: ResponseMode,
        override val state: String?,
        override val nonce: String,
        override val jarmRequirement: JarmRequirement?,
        val vpFormats: VpFormats,
        val presentationQuery: PresentationQuery,
        val transactionData: List<TransactionData>?,
    ) : ResolvedRequestObject

    /**
     * OpenId4VP combined with SIOPv2 request for presenting an id_token & vp_token
     */
    data class SiopOpenId4VPAuthentication(
        override val client: Client,
        override val responseMode: ResponseMode,
        override val state: String?,
        override val nonce: String,
        override val jarmRequirement: JarmRequirement?,
        val vpFormats: VpFormats,
        val idTokenType: List<IdTokenType>,
        val subjectSyntaxTypesSupported: List<SubjectSyntaxType>,
        val scope: Scope,
        val presentationQuery: PresentationQuery,
        val transactionData: List<TransactionData>?,
    ) : ResolvedRequestObject
}

/**
 * Errors that can occur while validating and resolving an authorization request
 */
sealed interface AuthorizationRequestError : Serializable

data class HttpError(val cause: Throwable) : AuthorizationRequestError

/**
 * Validation errors that can occur while validating an authorization request
 */
sealed interface RequestValidationError : AuthorizationRequestError {

    data class InvalidJarJwt(val cause: String) : AuthorizationRequestError

    data object InvalidUseOfBothRequestAndRequestUri : RequestValidationError {
        private fun readResolve(): Any = InvalidUseOfBothRequestAndRequestUri
    }

    data class UnsupportedRequestUriMethod(val method: RequestUriMethod) : RequestValidationError
    data object InvalidRequestUriMethod : RequestValidationError {
        private fun readResolve(): Any = InvalidRequestUriMethod
    }

    //
    // Response Type errors
    //
    data class UnsupportedResponseType(val value: String) : RequestValidationError

    data object MissingResponseType : RequestValidationError {
        private fun readResolve(): Any = MissingResponseType
    }

    //
    // Response Mode errors
    //
    data class UnsupportedResponseMode(val value: String?) : RequestValidationError

    //
    // Query source errors
    //
    data object MissingQuerySource : RequestValidationError {
        private fun readResolve(): Any = MissingQuerySource
    }

    data object MultipleQuerySources : RequestValidationError {
        private fun readResolve(): Any = MultipleQuerySources
    }

    data object InvalidClientId : RequestValidationError {
        private fun readResolve(): Any = InvalidClientId
    }

    data class InvalidPresentationDefinition(val cause: Throwable) : RequestValidationError

    data object InvalidPresentationDefinitionUri : RequestValidationError {
        private fun readResolve(): Any = InvalidPresentationDefinitionUri
    }

    data class InvalidDigitalCredentialsQuery(val cause: Throwable) : RequestValidationError

    data object InvalidRedirectUri : RequestValidationError {
        private fun readResolve(): Any = InvalidRedirectUri
    }

    data object MissingRedirectUri : RequestValidationError {
        private fun readResolve(): Any = MissingRedirectUri
    }

    data object MissingResponseUri : RequestValidationError {
        private fun readResolve(): Any = MissingResponseUri
    }

    data object InvalidResponseUri : RequestValidationError {
        private fun readResolve(): Any = InvalidResponseUri
    }

    data object ResponseUriMustNotBeProvided : RequestValidationError {
        private fun readResolve(): Any = ResponseUriMustNotBeProvided
    }

    data object RedirectUriMustNotBeProvided : RequestValidationError {
        private fun readResolve(): Any = RedirectUriMustNotBeProvided
    }

    data object MissingNonce : RequestValidationError {
        private fun readResolve(): Any = MissingNonce
    }

    data object MissingScope : RequestValidationError {
        private fun readResolve(): Any = MissingScope
    }

    data object MissingClientId : RequestValidationError {
        private fun readResolve(): Any = MissingClientId
    }

    data object UnsupportedClientIdScheme : RequestValidationError {
        private fun readResolve(): Any = UnsupportedClientIdScheme
    }

    data class UnsupportedClientMetaData(val value: String) : RequestValidationError

    data object OneOfClientMedataOrUri : RequestValidationError {
        private fun readResolve(): Any = OneOfClientMedataOrUri
    }

    data class InvalidClientMetaData(val cause: String) : RequestValidationError

    data object SubjectSyntaxTypesNoMatch : RequestValidationError {
        private fun readResolve(): Any = SubjectSyntaxTypesNoMatch
    }

    data object MissingClientMetadataJwksSource : RequestValidationError {
        private fun readResolve(): Any = MissingClientMetadataJwksSource
    }

    data object BothJwkUriAndInlineJwks : RequestValidationError {
        private fun readResolve(): Any = BothJwkUriAndInlineJwks
    }

    data object SubjectSyntaxTypesWrongSyntax : RequestValidationError {
        private fun readResolve(): Any = SubjectSyntaxTypesWrongSyntax
    }

    data object IdTokenSigningAlgMissing : RequestValidationError {
        private fun readResolve(): Any = IdTokenSigningAlgMissing
    }

    data object IdTokenEncryptionAlgMissing : RequestValidationError {
        private fun readResolve(): Any = IdTokenEncryptionAlgMissing
    }

    data object IdTokenEncryptionMethodMissing : RequestValidationError {
        private fun readResolve(): Any = IdTokenEncryptionMethodMissing
    }

    data class InvalidClientIdScheme(val value: String) : RequestValidationError

    data class InvalidIdTokenType(val value: String) : RequestValidationError

    data class DIDResolutionFailed(val didUrl: String) : RequestValidationError
}

/**
 * Errors that can occur while resolving an authorization request
 */
sealed interface ResolutionError : AuthorizationRequestError {
    data class UnknownScope(val scope: Scope) :
        ResolutionError

    data object FetchingPresentationDefinitionNotSupported : ResolutionError {
        private fun readResolve(): Any = FetchingPresentationDefinitionNotSupported
    }

    data class UnableToFetchPresentationDefinition(val cause: Throwable) : ResolutionError
    data class UnableToFetchRequestObject(val cause: Throwable) : ResolutionError
    data class ClientMetadataJwkUriUnparsable(val cause: Throwable) : ResolutionError
    data class ClientMetadataJwkResolutionFailed(val cause: Throwable) : ResolutionError
    data class InvalidTransactionData(val cause: Throwable) : ResolutionError
}

/**
 * An exception indicating an expected [error] while validating and/or resolving
 * an authorization request
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
 * The outcome of [validating and resolving][AuthorizationRequestResolver.resolveRequestUri]
 * an authorization request.
 */
sealed interface Resolution {
    /**
     * Represents the success of validating and resolving an authorization request
     * into a [requestObject]
     */
    data class Success(val requestObject: ResolvedRequestObject) : Resolution

    /**
     * Represents the failure of validating or resolving an authorization request
     * due to [error]
     */
    data class Invalid(val error: AuthorizationRequestError) : Resolution
}

/**
 * An interface that describes a service
 * that accepts an [authorization request]authorization request, validates it and resolves it (that is,
 * fetches parts of the authorization request which are provided by reference)
 *
 */
fun interface AuthorizationRequestResolver {

    /**
     * Tries to validate and request the provided [uri] into a [ResolvedRequestObject].
     */
    suspend fun resolveRequestUri(uri: String): Resolution
}

sealed interface PresentationQuery {

    @JvmInline
    value class ByPresentationDefinition(val value: PresentationDefinition) : PresentationQuery

    @JvmInline
    value class ByDigitalCredentialsQuery(val value: DCQL) : PresentationQuery
}
