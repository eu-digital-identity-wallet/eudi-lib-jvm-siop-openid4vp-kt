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

import com.nimbusds.jose.JWSAlgorithm
import eu.europa.ec.eudi.openid4vp.Client.*
import eu.europa.ec.eudi.openid4vp.ResolvedRequestObject.OpenId4VPAuthorization
import eu.europa.ec.eudi.openid4vp.ResolvedRequestObject.SiopOpenId4VPAuthentication
import eu.europa.ec.eudi.prex.PresentationDefinition
import org.bouncycastle.asn1.x500.X500Name
import org.bouncycastle.asn1.x500.style.BCStyle
import java.io.Serializable
import java.net.URI
import java.security.cert.X509Certificate

/**
 * Represents an OAuth2 RP that submitted an Authorization Request.
 */
sealed interface Client : Serializable {

    data class Preregistered(val clientId: String, val legalName: String) : Client
    data class RedirectUri(val clientId: URI) : Client
    data class X509SanDns(val clientId: String, val cert: X509Certificate) : Client
    data class X509SanUri(val clientId: URI, val cert: X509Certificate) : Client
    data class DIDClient(val clientId: URI) : Client
    data class Attested(val clientId: String) : Client

    /**
     * The id of the client.
     */
    val id: String
        get() = when (this) {
            is Preregistered -> clientId
            is RedirectUri -> clientId.toString()
            is X509SanDns -> clientId
            is X509SanUri -> clientId.toString()
            is DIDClient -> clientId.toString()
            is Attested -> clientId
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

sealed interface VpFormat : java.io.Serializable {
    data class SdJwtVc(
        val sdJwtAlgorithms: List<JWSAlgorithm>,
        val kbJwtAlgorithms: List<JWSAlgorithm>,
    ) : VpFormat

    data object MsoMdoc : VpFormat {
        private fun readResolve(): Any = MsoMdoc
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
        val vpFormats: List<VpFormat>,
        val presentationDefinition: PresentationDefinition,
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
        val vpFormats: List<VpFormat>,
        val idTokenType: List<IdTokenType>,
        val subjectSyntaxTypesSupported: List<SubjectSyntaxType>,
        val scope: Scope,
        val presentationDefinition: PresentationDefinition,
    ) : ResolvedRequestObject
}

/**
 * Errors that can occur while validating & resolving an authorization request
 */
sealed interface AuthorizationRequestError : Serializable

data class HttpError(val cause: Throwable) : AuthorizationRequestError

/**
 * Validation errors that can occur while validating an authorization request
 */
sealed interface RequestValidationError : AuthorizationRequestError {

    data class InvalidJarJwt(val cause: String) : AuthorizationRequestError

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
    // Presentation Definition errors
    //
    data object MissingPresentationDefinition : RequestValidationError {
        private fun readResolve(): Any = MissingPresentationDefinition
    }

    data object InvalidClientId : RequestValidationError {
        private fun readResolve(): Any = InvalidClientId
    }

    data class InvalidPresentationDefinition(val cause: Throwable) : RequestValidationError

    data object InvalidPresentationDefinitionUri : RequestValidationError {
        private fun readResolve(): Any = InvalidPresentationDefinitionUri
    }

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
    data class PresentationDefinitionNotFoundForScope(val scope: Scope) :
        ResolutionError

    data object FetchingPresentationDefinitionNotSupported : ResolutionError {
        private fun readResolve(): Any = FetchingPresentationDefinitionNotSupported
    }

    data class UnableToFetchPresentationDefinition(val cause: Throwable) : ResolutionError
    data class UnableToFetchRequestObject(val cause: Throwable) : ResolutionError
    data class ClientMetadataJwkUriUnparsable(val cause: Throwable) : ResolutionError
    data class ClientMetadataJwkResolutionFailed(val cause: Throwable) : ResolutionError
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
 * The outcome of [validating & resolving][AuthorizationRequestResolver.resolveRequestUri]
 * an authorization request.
 */
sealed interface Resolution {
    /**
     * Represents the success of validating & resolving an authorization request
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
