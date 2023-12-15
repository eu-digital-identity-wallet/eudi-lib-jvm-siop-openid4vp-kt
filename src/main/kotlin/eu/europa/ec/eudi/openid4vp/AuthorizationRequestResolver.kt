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

import eu.europa.ec.eudi.openid4vp.ResolvedRequestObject.OpenId4VPAuthorization
import eu.europa.ec.eudi.openid4vp.ResolvedRequestObject.SiopOpenId4VPAuthentication
import eu.europa.ec.eudi.openid4vp.internal.request.DefaultAuthorizationRequestResolver
import eu.europa.ec.eudi.prex.PresentationDefinition
import java.io.Serializable

/**
 * Represents an OAUTH2 authorization request. In particular
 * either a [SIOPv2 for id_token][SiopOpenId4VPAuthentication] or
 * a [OpenId4VP for vp_token][OpenId4VPAuthorization] or
 * a [SIOPv2 combined with OpenID4VP][SiopOpenId4VPAuthentication]
 */
sealed interface ResolvedRequestObject : Serializable {

    val responseMode: ResponseMode
    val clientMetaData: ClientMetaData
    val state: String
    val clientId: String

    /**
     * SIOPv2 Authentication request for issuing an id_token
     */
    data class SiopAuthentication(
        val idTokenType: List<IdTokenType>,
        override val clientMetaData: ClientMetaData,
        override val clientId: String,
        val nonce: String,
        override val responseMode: ResponseMode,
        override val state: String,
        val scope: Scope,
    ) : ResolvedRequestObject

    /**
     * OpenId4VP Authorization request for presenting a vp_token
     */
    data class OpenId4VPAuthorization(
        val presentationDefinition: PresentationDefinition,
        override val clientMetaData: ClientMetaData,
        override val clientId: String,
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
        override val clientMetaData: ClientMetaData,
        override val clientId: String,
        val nonce: String,
        override val responseMode: ResponseMode,
        override val state: String,
        val scope: Scope,
    ) : ResolvedRequestObject
}

/**
 * Errors that can occur while validating & resolving an authorization request
 */
sealed interface AuthorizationRequestError : Serializable

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

    data object MissingState : RequestValidationError {
        private fun readResolve(): Any = MissingState
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

    data object InvalidClientMetaDataUri : RequestValidationError {
        private fun readResolve(): Any = InvalidClientMetaDataUri
    }

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
    data class UnableToFetchClientMetadata(val cause: Throwable) : ResolutionError
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
 * that accepts an [authorization request]authorization request, validates it and resolves it (that is
 * fetches parts of the authorization request that are provided by reference)
 *
 */
fun interface AuthorizationRequestResolver {

    /**
     * Tries to validate and request the provided [uri] into a [ResolvedRequestObject].
     */
    suspend fun resolveRequestUri(uri: String): Resolution

    companion object {

        /**
         * A factory method for obtaining an instance of [AuthorizationRequestResolver]
         * Caller should provide a [KtorHttpClientFactory] instance.
         */
        operator fun invoke(
            httpClientFactory: KtorHttpClientFactory,
            walletOpenId4VPConfig: WalletOpenId4VPConfig,
        ): AuthorizationRequestResolver =
            DefaultAuthorizationRequestResolver.make(httpClientFactory, walletOpenId4VPConfig)
    }
}
