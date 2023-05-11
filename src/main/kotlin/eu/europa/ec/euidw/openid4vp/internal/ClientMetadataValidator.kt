package eu.europa.ec.euidw.openid4vp.internal

import com.nimbusds.jose.EncryptionMethod
import com.nimbusds.jose.JWEAlgorithm
import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.jwk.JWKSet
import com.nimbusds.openid.connect.sdk.rp.OIDCClientMetadata
import eu.europa.ec.euidw.openid4vp.*
import java.net.URL

internal class ClientMetadataValidator(
    private val walletOpenId4VPConfig: WalletOpenId4VPConfig
) {

    suspend fun validate(clientMetadata : ClientMetaData) : Result<OIDCClientMetadata> {
        val validSyntaxTypes = hasValidSubjectSyntaxTypes(clientMetadata)
        if (!validSyntaxTypes) {
            return RequestValidationError.SubjectSyntaxTypesWrongSyntax.asFailure()
        }
        // Validate if RP's client metadata supported_subject_types and OP's supported_subject_types have at least one common type
        val rpSupportedSyntaxTypes = parse(clientMetadata.subjectSyntaxTypesSupported)
        val typesMatch = rpSupportedSyntaxTypes.any { walletOpenId4VPConfig.subjectSyntaxTypesSupported.contains(it) }
        val jwksSourceΕxist = hasRequiredJwksSource(clientMetadata)
        return when {
            !typesMatch -> RequestValidationError.SubjectSyntaxTypesNoMatch.asFailure()
            !jwksSourceΕxist -> RequestValidationError.MissingClientMetadataJwksSource.asFailure()
            else ->  Result.success(valid(clientMetadata))
        }
    }

    private fun hasRequiredJwksSource(clientMetadata: ClientMetaData) : Boolean {
        val bothJwksSourcesDefined = !clientMetadata.jwks.isNullOrEmpty() && !clientMetadata.jwksUri.isNullOrEmpty()
        val atLeastOneJwkSourceDefined = !clientMetadata.jwks.isNullOrEmpty() || !clientMetadata.jwksUri.isNullOrEmpty()
        return !bothJwksSourcesDefined && atLeastOneJwkSourceDefined
    }

    private fun hasValidSubjectSyntaxTypes(clientMetadata: ClientMetaData) : Boolean {
        val listNotEmpty = !clientMetadata.subjectSyntaxTypesSupported.isEmpty()
        val allValidTypes = clientMetadata.subjectSyntaxTypesSupported.all(SubjectSyntaxType::isValid)
        return  listNotEmpty && allValidTypes
    }

    private suspend fun valid(clientMetaData: ClientMetaData) : OIDCClientMetadata {

        val vJwkSet = when {
            clientMetaData.jwksUri.isNullOrEmpty() -> JWKSet.parse(clientMetaData.jwks?.toString())
            else -> {
                // TODO this should be launched in coroutine, since it is blocking
                JWKSet.load(URL(clientMetaData.jwksUri))
            }
        }

        return OIDCClientMetadata().apply {
            idTokenJWSAlg = JWSAlgorithm.parse(clientMetaData.idTokenSignedResponseAlg)
            idTokenJWEAlg = JWEAlgorithm.parse(clientMetaData.idTokenEncryptedResponseAlg)
            idTokenJWEEnc = EncryptionMethod.parse(clientMetaData.idTokenEncryptedResponseEnc)
            jwkSet = vJwkSet
            setCustomField("subject_syntax_types_supported", parse(clientMetaData.subjectSyntaxTypesSupported))
        }
    }

    private fun parse(types: List<String>): List<SubjectSyntaxType> {
        return types.map {
            when {
                SubjectSyntaxType.JWKThumbprint.isValid(it) -> SubjectSyntaxType.JWKThumbprint
                SubjectSyntaxType.DecentralizedIdentifier.isValid(it) -> SubjectSyntaxType.DecentralizedIdentifier(it)
                else -> throw IllegalArgumentException("Cannot convert value $it to a supported SubjectSyntaxType")
            }
        }
    }
}