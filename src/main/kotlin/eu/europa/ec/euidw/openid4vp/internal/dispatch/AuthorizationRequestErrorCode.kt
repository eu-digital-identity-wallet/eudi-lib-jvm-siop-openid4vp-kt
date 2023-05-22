package eu.europa.ec.euidw.openid4vp.internal.dispatch

import eu.europa.ec.euidw.openid4vp.AuthorizationRequestError
import eu.europa.ec.euidw.openid4vp.RequestValidationError.*
import eu.europa.ec.euidw.openid4vp.ResolutionError.*


enum class AuthorizationRequestErrorCode(val code: String) {

    /**
     * OpenId4VP Error Codes
     */
    INVALID_SCOPE("invalid_scope"),
    INVALID_REQUEST("invalid_request"),
    INVALID_CLIENT("invalid_client"),
    VP_FORMATS_NOT_SUPPORTED("vp_formats_not_supported"),
    INVALID_PRESENTATION_DEFINITION_URI("invalid_presentation_definition_uri"),
    INVALID_PRESENTATION_DEFINITION_REFERENCE("invalid_presentation_definition_reference"),

    /**
     * SIOPv2 Error Codes
     */
    USER_CANCELLED("user_cancelled"),
    REGISTRATION_VALUE_NOT_SUPPORTED("registration_value_not_supported"),
    SUBJECT_SYNTAX_TYPES_NOT_SUPPORTED("subject_syntax_types_not_supported"),
    INVALID_REGISTRATION_URI("invalid_registration_uri"),
    INVALID_REGISTRATION_OBJECT("invalid_registration_object"),

    PROCESSING_FAILURE("processing_error");

    companion object {

        /**
         * Maps an [error] into a [AuthorizationRequestErrorCode]
         */
        fun fromError(error: AuthorizationRequestError): AuthorizationRequestErrorCode {
            return when (error) {
                is InvalidClientIdScheme,
                InvalidRedirectUri,
                InvalidResponseUri,
                MissingClientId,
                MissingNonce,
                MissingPresentationDefinition,
                MissingRedirectUri,
                MissingResponseType,
                MissingResponseUri,
                MissingScope,
                MissingState,
                OneOfClientMedataOrUri,
                RedirectUriMustNotBeProvided,
                ResponseUriMustNotBeProvided,
                is UnsupportedResponseMode,
                is UnsupportedResponseType,
                is InvalidIdTokenType -> INVALID_REQUEST

                BothJwkUriAndInlineJwks,
                MissingClientMetadataJwksSource -> INVALID_REGISTRATION_OBJECT

                SubjectSyntaxTypesNoMatch,
                SubjectSyntaxTypesWrongSyntax -> SUBJECT_SYNTAX_TYPES_NOT_SUPPORTED

                is ClientMetadataJwkUriUnparsable,
                InvalidClientMetaDataUri -> INVALID_REGISTRATION_URI

                is InvalidPresentationDefinition -> INVALID_PRESENTATION_DEFINITION_REFERENCE
                InvalidPresentationDefinitionUri -> INVALID_PRESENTATION_DEFINITION_URI
                is ClientMetadataJwkResolutionFailed,
                FetchingPresentationDefinitionNotSupported,
                is PresentationDefinitionNotFoundForScope,
                is UnableToFetchClientMetadata,
                is UnableToFetchPresentationDefinition,
                is UnableToFetchRequestObject -> PROCESSING_FAILURE
            }

        }
    }
}