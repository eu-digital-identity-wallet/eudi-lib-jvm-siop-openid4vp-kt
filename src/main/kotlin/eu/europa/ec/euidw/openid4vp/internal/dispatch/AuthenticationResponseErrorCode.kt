package eu.europa.ec.euidw.openid4vp.internal.dispatch

import eu.europa.ec.euidw.openid4vp.AuthorizationRequestError
import eu.europa.ec.euidw.openid4vp.RequestValidationError.*
import eu.europa.ec.euidw.openid4vp.ResolutionError.*

enum class AuthenticationResponseErrorCode(
    val code: String,
    val description: String
) {


    /**
     * OpenId4VP Error Codes
     */
    INVALID_SCOPE("invalid_scope", "invalid_scope"),
    INVALID_REQUEST("invalid_request", "invalid_request"),
    INVALID_CLIENT("invalid_client", "invalid_client"),
    VP_FORMATS_NOT_SUPPORTED("vp_formats_not_supported", "vp_formats_not_supported"),
    INVALID_PRESENTATION_DEFINITION_URI("invalid_presentation_definition_uri", "invalid_presentation_definition_uri"),
    INVALID_PRESENTATION_DEFINITION_REFERENCE(
        "invalid_presentation_definition_reference",
        "invalid_presentation_definition_reference"
    ),

    /**
     * SIOPv2 Error Codes
     */
    USER_CANCELLED("user_cancelled", "user_cancelled"),
    REGISTRATION_VALUE_NOT_SUPPORTED("registration_value_not_supported", "registration_value_not_supported"),
    SUBJECT_SYNTAX_TYPES_NOT_SUPPORTED("subject_syntax_types_not_supported", "subject_syntax_types_not_supported"),
    INVALID_REGISTRATION_URI("invalid_registration_uri", "invalid_registration_uri"),
    INVALID_REGISTRATION_OBJECT("invalid_registration_object", "invalid_registration_object"),

    PROCESSING_FAILURE("processing_error", "processing_error");

    operator fun component1(): String = code
    operator fun component2(): String = description

    companion object {
        fun fromError(error: AuthorizationRequestError): AuthenticationResponseErrorCode {
            return when (error) {
                is InvalidClientIdScheme, InvalidRedirectUri, InvalidResponseUri, MissingClientId,
                MissingNonce, MissingPresentationDefinition, MissingRedirectUri, MissingResponseType,
                MissingResponseUri, MissingScope, MissingState, OneOfClientMedataOrUri, RedirectUriMustNotBeProvided,
                ResponseUriMustNotBeProvided, is UnsupportedResponseMode, is UnsupportedResponseType
                -> INVALID_REQUEST

                BothJwkUriAndInlineJwks, MissingClientMetadataJwksSource -> INVALID_REGISTRATION_OBJECT
                SubjectSyntaxTypesNoMatch, SubjectSyntaxTypesWrongSyntax -> SUBJECT_SYNTAX_TYPES_NOT_SUPPORTED
                is ClientMetadataJwkUriUnparsable, InvalidClientMetaDataUri -> INVALID_REGISTRATION_URI
                is InvalidPresentationDefinition -> INVALID_PRESENTATION_DEFINITION_REFERENCE
                InvalidPresentationDefinitionUri -> INVALID_PRESENTATION_DEFINITION_URI
                is ClientMetadataJwkResolutionFailed, FetchingPresentationDefinitionNotSupported, is PresentationDefinitionNotFoundForScope,
                is UnableToFetchClientMetadata, is UnableToFetchPresentationDefinition, is UnableToFetchRequestObject
                -> PROCESSING_FAILURE
            }
        }
    }

}