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

    /**
     * OpenId4VP Error Codes
     */
    INVALID_SCOPE("invalid_scope"),
    INVALID_REQUEST("invalid_request"),
    INVALID_CLIENT("invalid_client"),
    VP_FORMATS_NOT_SUPPORTED("vp_formats_not_supported"),
    INVALID_PRESENTATION_DEFINITION_URI("invalid_presentation_definition_uri"),
    INVALID_PRESENTATION_DEFINITION_REFERENCE("invalid_presentation_definition_reference"),
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
                InvalidClientId, UnsupportedClientIdScheme -> INVALID_CLIENT

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
                OneOfClientMedataOrUri,
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
                InvalidRequestUriMethod,
                InvalidUseOfBothRequestAndRequestUri,
                is UnsupportedRequestUriMethod,
                -> INVALID_REQUEST

                BothJwkUriAndInlineJwks,
                MissingClientMetadataJwksSource,
                -> INVALID_REGISTRATION_OBJECT

                SubjectSyntaxTypesNoMatch,
                SubjectSyntaxTypesWrongSyntax,
                -> SUBJECT_SYNTAX_TYPES_NOT_SUPPORTED

                is ClientMetadataJwkUriUnparsable,
                -> INVALID_REGISTRATION_URI

                is InvalidPresentationDefinition -> INVALID_PRESENTATION_DEFINITION_REFERENCE
                InvalidPresentationDefinitionUri -> INVALID_PRESENTATION_DEFINITION_URI
                is ClientMetadataJwkResolutionFailed,
                FetchingPresentationDefinitionNotSupported,
                is UnknownScope,
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
