package eu.europa.ec.euidw.openid4vp.internal.request

import com.nimbusds.jose.EncryptionMethod
import com.nimbusds.jose.JWEAlgorithm
import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.jwk.JWKSet
import com.nimbusds.openid.connect.sdk.rp.OIDCClientMetadata
import eu.europa.ec.euidw.openid4vp.*
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.io.IOException
import java.net.URL
import java.text.ParseException

internal object ClientMetadataValidator {

    suspend fun validate(clientMetadata: ClientMetaData): Result<OIDCClientMetadata> = runCatching {

        val jwkSets = parseRequiredJwks(clientMetadata).getOrThrow()
        val types = parseRequiredSubjectSyntaxTypes(clientMetadata).getOrThrow()

        OIDCClientMetadata().apply {
            idTokenJWSAlg = JWSAlgorithm.parse(clientMetadata.idTokenSignedResponseAlg)
            idTokenJWEAlg = JWEAlgorithm.parse(clientMetadata.idTokenEncryptedResponseAlg)
            idTokenJWEEnc = EncryptionMethod.parse(clientMetadata.idTokenEncryptedResponseEnc)
            jwkSet = jwkSets
            setCustomField("subject_syntax_types_supported", types)
        }

        // Validate if RP's client metadata supported_subject_types and OP's supported_subject_types have at least one common type
        // val typesMatch = rpSupportedSyntaxTypes.any { walletOpenId4VPConfig.subjectSyntaxTypesSupported.contains(it) }

    }

    private suspend fun parseRequiredJwks(clientMetadata: ClientMetaData): Result<JWKSet> {
        val bothJwksSourcesDefined = !clientMetadata.jwks.isNullOrEmpty() && !clientMetadata.jwksUri.isNullOrEmpty()
        val atLeastOneJwkSourceDefined = !clientMetadata.jwks.isNullOrEmpty() || !clientMetadata.jwksUri.isNullOrEmpty()

        if (!atLeastOneJwkSourceDefined) {
            return RequestValidationError.MissingClientMetadataJwksSource.asFailure()
        }
        if (bothJwksSourcesDefined) {
            return RequestValidationError.BothJwkUriAndInlineJwks.asFailure()
        }
        when {
            clientMetadata.jwksUri.isNullOrEmpty() -> {
                return try {
                    Result.success(JWKSet.parse(clientMetadata.jwks?.toString()))
                } catch (ex: ParseException) {
                    ResolutionError.ClientMetadataJwkUriUnparsable(ex).asFailure()
                }
            }

            else -> {
                // TODO this should be launched in coroutine, since it is blocking
                return withContext(Dispatchers.IO) {
                    try {
                        Result.success(JWKSet.load(URL(clientMetadata.jwksUri)))
                    } catch (ex: IOException) {
                        ResolutionError.ClientMetadataJwkResolutionFailed(ex).asFailure()
                    } catch (ex: ParseException) {
                        ResolutionError.ClientMetadataJwkResolutionFailed(ex).asFailure()
                    }
                }
            }
        }
    }

    private fun parseRequiredSubjectSyntaxTypes(clientMetadata: ClientMetaData): Result<List<SubjectSyntaxType>> {
        val listNotEmpty = clientMetadata.subjectSyntaxTypesSupported.isNotEmpty()
        val allValidTypes = clientMetadata.subjectSyntaxTypesSupported.all(SubjectSyntaxType::isValid)
        return when {
            listNotEmpty && allValidTypes -> {
                Result.success(clientMetadata.subjectSyntaxTypesSupported.map {
                    when {
                        SubjectSyntaxType.JWKThumbprint.isValid(it) -> SubjectSyntaxType.JWKThumbprint
                        else -> SubjectSyntaxType.DecentralizedIdentifier.parse(it)
                    }
                })
            }

            else -> RequestValidationError.SubjectSyntaxTypesWrongSyntax.asFailure()
        }
    }

}