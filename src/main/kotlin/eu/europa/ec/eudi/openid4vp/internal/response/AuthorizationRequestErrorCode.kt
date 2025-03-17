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
package eu.europa.ec.eudi.openid4vp.internal.response

import eu.europa.ec.eudi.openid4vp.AuthorizationRequestError
import eu.europa.ec.eudi.openid4vp.HttpError
import eu.europa.ec.eudi.openid4vp.RequestValidationError.*
import eu.europa.ec.eudi.openid4vp.ResolutionError.*

internal enum class AuthorizationRequestErrorCode(val code: String) {

    // OAUTH2

    /**
     * Requested scope value is invalid, unknown, or malformed
     */
    INVALID_SCOPE("invalid_scope"),

    /**
     * One of the following:
     *
     * The request contains more than one out of the following three options to communicate a requested Credential:
     * a presentation_definition parameter, a presentation_definition_uri parameter,
     * or a scope value representing a Presentation Definition
     *
     * The request uses the vp_token Response Type but does not request a Credential using any of the three options
     *
     * Requested Presentation Definition does not conform to the DIF PEv2 specification
     *
     * The Wallet does not support the Client Identifier Scheme passed in the Authorization Request
     *
     * The Client Identifier passed in the request did not belong to its Client Identifier scheme,
     * or requirements of a certain scheme was violated,
     * for example, an unsigned request was sent with Client Identifier scheme https
     */
    INVALID_REQUEST("invalid_request"),
    ACCESS_DENIED("access_denied"),

    /**
     * OpenId4VP Error Codes
     */
    INVALID_CLIENT("invalid_client"),
    VP_FORMATS_NOT_SUPPORTED("vp_formats_not_supported"),
    INVALID_PRESENTATION_DEFINITION_URI("invalid_presentation_definition_uri"),
    INVALID_PRESENTATION_DEFINITION_REFERENCE("invalid_presentation_definition_reference"),
    INVALID_REQUEST_URI_METHOD("invalid_request_uri_method"),
    INVALID_TRANSACTION_DATA("invalid_transaction_data"),

    /**
     * SIOPv2 Error Codes
     */
    USER_CANCELLED("user_cancelled"),
    REGISTRATION_VALUE_NOT_SUPPORTED("registration_value_not_supported"),
    SUBJECT_SYNTAX_TYPES_NOT_SUPPORTED("subject_syntax_types_not_supported"),
    INVALID_REGISTRATION_URI("invalid_registration_uri"),
    INVALID_REGISTRATION_OBJECT("invalid_registration_object"),

    PROCESSING_FAILURE("processing_error"),
    ;

    companion object {

        /**
         * Maps an [error] into a [AuthorizationRequestErrorCode]
         */
        fun fromError(error: AuthorizationRequestError): AuthorizationRequestErrorCode {
            return when (error) {
                is UnknownScope -> INVALID_SCOPE
                is InvalidJarJwt,
                is InvalidClientIdScheme,
                InvalidRedirectUri,
                InvalidResponseUri,
                MissingClientId,
                MissingNonce,
                MissingQuerySource,
                MultipleQuerySources,
                is InvalidDigitalCredentialsQuery,
                MissingRedirectUri,
                MissingResponseType,
                MissingResponseUri,
                MissingScope,
                RedirectUriMustNotBeProvided,
                ResponseUriMustNotBeProvided,
                IdTokenSigningAlgMissing,
                IdTokenEncryptionAlgMissing,
                IdTokenEncryptionMethodMissing,
                is InvalidClientMetaData,
                is UnsupportedResponseMode,
                is UnsupportedResponseType,
                is UnsupportedClientMetaData,
                is InvalidIdTokenType,
                is HttpError,
                InvalidUseOfBothRequestAndRequestUri,
                is UnsupportedRequestUriMethod,
                -> INVALID_REQUEST

                InvalidClientId, UnsupportedClientIdScheme -> INVALID_CLIENT

                is InvalidRequestUriMethod -> INVALID_REQUEST_URI_METHOD

                BothJwkUriAndInlineJwks,
                MissingClientMetadataJwksSource,
                -> INVALID_REGISTRATION_OBJECT

                SubjectSyntaxTypesNoMatch,
                SubjectSyntaxTypesWrongSyntax,
                -> SUBJECT_SYNTAX_TYPES_NOT_SUPPORTED

                is ClientMetadataJwkUriUnparsable -> INVALID_REGISTRATION_URI
                is InvalidPresentationDefinition -> INVALID_PRESENTATION_DEFINITION_REFERENCE
                InvalidPresentationDefinitionUri -> INVALID_PRESENTATION_DEFINITION_URI

                is ClientMetadataJwkResolutionFailed,
                FetchingPresentationDefinitionNotSupported,
                is UnableToFetchPresentationDefinition,
                is UnableToFetchRequestObject,
                is DIDResolutionFailed,
                -> PROCESSING_FAILURE

                is InvalidTransactionData -> INVALID_TRANSACTION_DATA

                ClientVpFormatsNotSupportedFromWallet -> VP_FORMATS_NOT_SUPPORTED
            }
        }
    }
}
